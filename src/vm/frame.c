#include <bitmap.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "frame.h"

static void *user_base; // Mapped Kernel Address of User Pool Base
static size_t user_page_count;
static struct frame *frames;
static struct lock frames_lock;

void frame_init(void *_user_base, size_t _user_page_count)
{
  user_base = _user_base;
  user_page_count = _user_page_count;
  frames = malloc(sizeof(struct frame) * user_page_count);
  lock_init(&frames_lock);
}

size_t frame_index(void *ptr) // ptr should be a mapped kernel address
{
  size_t index = (ptr - user_base) / PGSIZE;
  if (index >= user_page_count)
    PANIC("get_frame_of: index out of range");
  return index;
}

struct frame *frame_of(void *ptr) // ptr should be a mapped kernel address
{
  return &frames[frame_index(ptr)];
}

struct frame *frame_alloc()
{
  void *page = palloc_get_page(PAL_USER | PAL_ZERO | PAL_ASSERT);
  // TODO: implement eviction
  struct frame *frame = frame_of(page);
  frame->kpage = page;
  return frame;
}

void frame_free(struct frame *frame)
{
  lock_acquire(&frames_lock);
  palloc_free_page(frame->kpage);
  lock_release(&frames_lock);
}