#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdint.h>
#include <stddef.h>
#include "filesys/file.h"
#include "vm/swap.h"

enum page_info_state
{
  PIS_ACTIVE = 0, // active page
  PIS_SWAP = 1,   // swapped page
  PIS_ZERO = 2,   // page that should be zeroed
  PIS_FILE = 3,   // file-backed page
};

struct page_info_file
{
  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
};

struct page_info_swap
{
  swap_idx_t idx;
};

union page_info_data
{
  struct page_info_file file;
  struct page_info_swap swap;
};

struct page_info
{
  uint32_t *pagedir;
  void *upage;
  bool writable;
  enum page_info_state state;
  struct hash_elem hash_elem;
  union page_info_data data;
};

void page_init(void);
void page_swap_in(uint32_t *pagedir, void *fault_addr);
void page_swap_out(uint32_t *pagedir, void *upage);
void page_map_file(uint32_t *pagedir, void *upage, struct file *file, off_t ofs, size_t read_bytes, bool writable);
void page_map_zero(uint32_t *pagedir, void *upage, bool writable);

#endif