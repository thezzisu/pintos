#include <string.h>
#include "page.h"
#include "frame.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/stdio.h"

static unsigned page_info_hash(const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page_info *p = hash_entry(p_, struct page_info, hash_elem);
  return hash_bytes(&p->pagedir, sizeof(p->pagedir) + sizeof(p->upage));
}

static bool page_info_less(const struct hash_elem *a_, const struct hash_elem *b_,
                           void *aux UNUSED)
{
  const struct page_info *a = hash_entry(a_, struct page_info, hash_elem);
  const struct page_info *b = hash_entry(b_, struct page_info, hash_elem);

  return a->pagedir < b->pagedir || (a->pagedir == b->pagedir && a->upage < b->upage);
}

static struct hash page_infos;
static struct lock page_infos_lock;

void page_init(void)
{
  hash_init(&page_infos, page_info_hash, page_info_less, NULL);
  lock_init(&page_infos_lock);
}

static bool load_file_into(struct file *file, off_t ofs, uint32_t read_bytes, void *kpage)
{
  file_seek(file, ofs);
  if (file_read(file, kpage, read_bytes) != (int)read_bytes)
  {
    return false;
  }
  memset(kpage + read_bytes, 0, PGSIZE - read_bytes);
  return true;
}

static bool dump_mem_into(struct file *file, off_t ofs, uint32_t write_bytes, void *kpage)
{
  file_seek(file, ofs);
  off_t off = file_write(file, kpage, write_bytes);
  if (off != (int)write_bytes)
  {
    printf("Write failed for %p %d %d %d\n", kpage, ofs, off, write_bytes);
    return false;
  }
  return true;
}

static struct page_info *get_page_info(uint32_t *pagedir, void *fault_addr)
{
  struct page_info p;
  p.pagedir = pagedir;
  p.upage = pg_round_down(fault_addr);
  lock_acquire(&page_infos_lock);
  struct hash_elem *e = hash_find(&page_infos, &p.hash_elem);
  if (e == NULL)
  {
    lock_release(&page_infos_lock);
    return NULL;
  }
  struct page_info *info = hash_entry(e, struct page_info, hash_elem);
  lock_release(&page_infos_lock);
  return info;
}

bool page_exists(uint32_t *pagedir, void *fault_addr)
{
  return get_page_info(pagedir, fault_addr) != NULL;
}

void page_swap_in(uint32_t *pagedir, void *fault_addr, bool allow_map)
{
  struct page_info *info = get_page_info(pagedir, fault_addr);
  if (!info)
  {
    struct thread *cur = thread_current();
    if (!allow_map)
    {
      cur->state->exit_code = -1;
      thread_exit();
    }
    if (++cur->user_stack_pages > MAX_STACK_PAGES)
    {
      cur->state->exit_code = -1;
      thread_exit();
    }
    void *base = pg_round_down(fault_addr);
    page_map_zero(pagedir, base, true);
    info = get_page_info(pagedir, fault_addr);
  }
  lock_acquire(&info->lock);
  if (info->state != PIS_SWAP)
  {
    PANIC("Attempted to swap in non-swap page");
  }
  struct frame *frame = frame_alloc();
  bool success = false;
  switch (info->backend_type)
  {
  case PB_NONE:
    PANIC("Attempted to swap in page with no backend");
  case PB_SWAP:
    swap_in(info->backend.swap.idx, frame->kpage);
    success = true;
    break;
  case PB_ZERO:
    memset(frame->kpage, 0, PGSIZE);
    success = true;
    break;
  case PB_FILE:
    success = load_file_into(info->backend.file.file, info->backend.file.ofs, info->backend.file.size, frame->kpage);
    if (!info->backend.file.write_back)
    {
      file_close(info->backend.file.file);
      info->backend_type = PB_NONE;
    }
    break;
  }
  info->state = PIS_ACTIVE;
  info->kpage = frame->kpage;
  success = success && pagedir_set_page(pagedir, info->upage, frame->kpage, info->writable);
  lock_release(&info->lock);
  if (success)
  {
    frame->pagedir = pagedir;
    frame->upage = info->upage;
  }
  else
  {
    PANIC("Failed to swap in page");
  }
}

void page_swap_out(uint32_t *pagedir, void *upage)
{
  struct page_info *info = get_page_info(pagedir, upage);
  if (!info)
  {
    PANIC("Attempted to swap out non-existent page");
  }
  lock_acquire(&info->lock);
  if (info->state != PIS_ACTIVE)
  {
    lock_release(&info->lock);
    return;
  }
  bool dirty = pagedir_is_dirty(pagedir, info->upage);
  pagedir_clear_page(pagedir, info->upage);
  info->state = PIS_SWAP;
  switch (info->backend_type)
  {
  case PB_SWAP:
    if (dirty)
    {
      swap_out(info->backend.swap.idx, info->kpage);
    }
    break;
  case PB_ZERO:
  case PB_NONE:
    info->backend_type = PB_SWAP;
    info->backend.swap.idx = swap_alloc();
    swap_out(info->backend.swap.idx, info->kpage);
    break;
  case PB_FILE:
    if (dirty)
    {
      if (!dump_mem_into(info->backend.file.file, info->backend.file.ofs, info->backend.file.size, info->kpage))
      {
        PANIC("Failed to dump memory into file");
      }
    }
    break;
  }
  lock_release(&info->lock);
}

void page_map_file(uint32_t *pagedir, void *upage, struct file *file, off_t ofs, size_t read_bytes, bool writable, bool write_back)
{
  struct page_info *info = malloc(sizeof(struct page_info));
  info->pagedir = pagedir;
  info->upage = upage;
  info->writable = writable;
  info->state = PIS_SWAP;
  info->backend_type = PB_FILE;
  info->backend.file.file = file_reopen(file);
  info->backend.file.ofs = ofs;
  info->backend.file.size = read_bytes;
  info->backend.file.write_back = write_back;
  lock_init(&info->lock);
  lock_acquire(&page_infos_lock);
  hash_insert(&page_infos, &info->hash_elem);
  lock_release(&page_infos_lock);
}

void page_map_zero(uint32_t *pagedir, void *upage, bool writable)
{
  struct page_info *info = malloc(sizeof(struct page_info));
  info->pagedir = pagedir;
  info->upage = upage;
  info->writable = writable;
  info->state = PIS_SWAP;
  info->backend_type = PB_ZERO;
  lock_init(&info->lock);
  lock_acquire(&page_infos_lock);
  hash_insert(&page_infos, &info->hash_elem);
  lock_release(&page_infos_lock);
}

void page_destroy(uint32_t *pagedir, void *upage)
{
  struct page_info *info = get_page_info(pagedir, upage);
  if (!info)
    return;
  lock_acquire(&info->lock);
  info->state = PIS_DIE;
  lock_release(&info->lock);
  if (info->state == PIS_ACTIVE)
  {
    frame_free(info->kpage);
  }
  bool dirty = pagedir_is_dirty(pagedir, info->upage);
  switch (info->backend_type)
  {
  case PB_FILE:
    if (dirty && info->backend.file.write_back)
      dump_mem_into(info->backend.file.file, info->backend.file.ofs, info->backend.file.size, info->kpage);
    file_close(info->backend.file.file);
    break;
  default:
    break;
  }
  lock_acquire(&page_infos_lock);
  hash_delete(&page_infos, &info->hash_elem);
  lock_release(&page_infos_lock);
  free(info);
}