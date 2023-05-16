#include <bitmap.h>
#include "swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct block *swap_block;
static size_t swap_size;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

void swap_init(void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  if (!swap_block)
  {
    PANIC("Swap block not found");
  }
  swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_bitmap = bitmap_create(swap_size);
  lock_init(&swap_lock);
}

swap_idx_t swap_alloc()
{
  lock_acquire(&swap_lock);
  swap_idx_t idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  lock_release(&swap_lock);

  if (idx == BITMAP_ERROR)
  {
    PANIC("Swap is full");
  }

  return idx;
}

void swap_free(swap_idx_t idx)
{
  lock_acquire(&swap_lock);
  bitmap_flip(swap_bitmap, idx);
  lock_release(&swap_lock);
}

void swap_in(swap_idx_t idx, void *kaddr)
{
  size_t counter = 0;
  while (counter < SECTORS_PER_PAGE)
  {
    block_read(swap_block, idx * SECTORS_PER_PAGE + counter,
               kaddr + counter * BLOCK_SECTOR_SIZE);
    counter++;
  }
}

void swap_out(swap_idx_t idx, void *kaddr)
{
  size_t counter = 0;
  while (counter < SECTORS_PER_PAGE)
  {
    block_write(swap_block, idx * SECTORS_PER_PAGE + counter,
                kaddr + counter * BLOCK_SECTOR_SIZE);
    counter++;
  }
}
