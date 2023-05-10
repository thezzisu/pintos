#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include <stddef.h>

struct frame
{
  void *kpage; // Kernel-mapped physical address

  void *upage;       // The virtual address of this frame
  uint32_t *pagedir; // The Page Directory that owns this frame
};

void frame_init(void *, size_t);
struct frame *frame_of(void *);
struct frame *frame_alloc(void);
void frame_free(struct frame *);

#endif