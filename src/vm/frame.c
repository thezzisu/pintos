/**
 * Frames are binded to user pages.
 * No code except page.c should be able to access frames directly.
 */
#include <bitmap.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "frame.h"
#include "page.h"
#include "userprog/pagedir.h"

static void *user_base; // Mapped Kernel Address of User Pool Base
static size_t user_page_count;
static struct frame *frames;
static struct lock frames_lock;
static int clock_hand;

void frame_init(void *_user_base, size_t _user_page_count)
{
  user_base = _user_base;
  user_page_count = _user_page_count;
  frames = malloc(sizeof(struct frame) * user_page_count);
  memset(frames, 0, sizeof(struct frame) * user_page_count);
  lock_init(&frames_lock);
}

static size_t frame_index(void *kaddr)
{
  size_t index = (kaddr - user_base) / PGSIZE;
  if (index >= user_page_count)
    PANIC("get_frame_of: index out of range");
  return index;
}

static struct frame *frame_of(void *kaddr)
{
  return &frames[frame_index(kaddr)];
}

static struct frame *frame_evict(void)
{
  lock_acquire(&frames_lock);
  struct frame *frame = NULL;
  for (; frame == NULL; clock_hand = (clock_hand + 1) % user_page_count)
  {
    frame = &frames[clock_hand];
    if (frame->pagedir == NULL)
    {
      frame = NULL;
      continue;
    }

    if (pagedir_is_accessed(frame->pagedir, frame->upage))
    {
      pagedir_set_accessed(frame->pagedir, frame->upage, false);
      frame = NULL;
    }
  }
  uint32_t *pd = frame->pagedir;
  void *upage = frame->upage;
  frame->pagedir = NULL;
  frame->upage = NULL;
  lock_release(&frames_lock);
  page_swap_out(pd, upage);
  return frame;
}

struct frame *frame_alloc()
{
  void *page = palloc_get_page(PAL_USER | PAL_ZERO);
  if (page)
  {
    struct frame *frame = frame_of(page);
    frame->kpage = page;
    return frame;
  }
  else
  {
    return frame_evict();
  }
}

void frame_free(void *kaddr)
{
  struct frame *frame = frame_of(kaddr);
  lock_acquire(&frames_lock);
  frame->pagedir = NULL;
  frame->upage = NULL;
  lock_release(&frames_lock);
}