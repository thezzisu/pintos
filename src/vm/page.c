#include <string.h>
#include "page.h"
#include "frame.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"

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

void page_init(void)
{
  hash_init(&page_infos, page_info_hash, page_info_less, NULL);
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

void page_swap_in(uint32_t *pagedir, void *fault_addr)
{
  struct page_info p;
  p.pagedir = pagedir;
  p.upage = pg_round_down(fault_addr);
  struct hash_elem *e = hash_find(&page_infos, &p.hash_elem);
  if (e == NULL)
  {
    thread_current()->state->exit_code = -1;
    thread_exit();
  }
  struct page_info *info = hash_entry(e, struct page_info, hash_elem);
  struct frame *frame = frame_alloc();
  bool success = false;
  switch (info->state)
  {
  case PIS_ACTIVE:
    PANIC("Page is active");
    break;
  case PIS_SWAP:
    swap_in(info->data.swap.idx, frame->kpage);
    success = true;
    break;
  case PIS_ZERO:
    memset(frame->kpage, 0, PGSIZE);
    success = true;
    break;
  case PIS_FILE:
    success = load_file_into(info->data.file.file, info->data.file.ofs, info->data.file.read_bytes, frame->kpage);
    break;
  }
  success = success && pagedir_set_page(pagedir, p.upage, frame->kpage, true);
  if (!success)
  {
    frame_free(frame);
    PANIC("Failed to swap in page");
  }
}

void page_swap_out(uint32_t *pagedir, void *upage)
{
  PANIC("TODO: page_swap_out");
}

void page_map_file(uint32_t *pagedir, void *upage, struct file *file, off_t ofs, size_t read_bytes, bool writable)
{
  struct page_info *info = malloc(sizeof(struct page_info));
  info->pagedir = pagedir;
  info->upage = upage;
  info->writable = writable;
  info->state = PIS_FILE;
  info->data.file.file = file_reopen(file);
  info->data.file.ofs = ofs;
  info->data.file.read_bytes = read_bytes;
  hash_insert(&page_infos, &info->hash_elem);
}

void page_map_zero(uint32_t *pagedir, void *upage, bool writable)
{
  struct page_info *info = malloc(sizeof(struct page_info));
  info->pagedir = pagedir;
  info->upage = upage;
  info->writable = writable;
  info->state = PIS_ZERO;
  hash_insert(&page_infos, &info->hash_elem);
}