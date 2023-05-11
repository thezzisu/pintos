#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <hash.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

typedef uint32_t swap_idx_t;

void swap_init(void);
void swap_in(swap_idx_t idx, void *kaddr);
void swap_free(swap_idx_t idx);
swap_idx_t swap_out(void *kaddr);

#endif