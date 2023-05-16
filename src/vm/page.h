#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdint.h>
#include <stddef.h>
#include "filesys/file.h"
#include "vm/swap.h"
#include "threads/synch.h"

enum page_state
{
  PIS_ACTIVE = 0, // active page
  PIS_SWAP = 1,   // swapped page
  PIS_DIE = 2,    // page that should be freed
};

enum page_backend_type
{
  PB_NONE = 0,
  PB_FILE = 1,
  PB_SWAP = 2,
  PB_ZERO = 3
};

struct page_backend_file
{
  struct file *file;
  off_t ofs;
  uint32_t size;
  bool write_back;
};

struct page_backend_swap
{
  swap_idx_t idx;
};

union page_backend
{
  struct page_backend_file file;
  struct page_backend_swap swap;
};

struct page_info
{
  uint32_t *pagedir;
  void *upage;
  bool writable;
  enum page_state state;
  void *kpage;
  enum page_backend_type backend_type;
  union page_backend backend;

  struct hash_elem hash_elem;
  struct lock lock;
};

void page_init(void);
void page_swap_in(uint32_t *pagedir, void *fault_addr, bool allow_map);
void page_swap_out(uint32_t *pagedir, void *upage);
bool page_exists(uint32_t *pagedir, void *upage);
void page_map_file(uint32_t *pagedir, void *upage, struct file *file, off_t ofs, size_t read_bytes, bool writable, bool write_back);
void page_map_zero(uint32_t *pagedir, void *upage, bool writable);
void page_destroy(uint32_t *pagedir, void *upage);

#endif