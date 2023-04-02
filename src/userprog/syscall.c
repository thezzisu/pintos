#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void
thread_panic(void)
{
  thread_current()->state->exit_code = -1;
  thread_exit();
}

static void
check_uaddr(const void *uaddr)
{
  if (is_user_vaddr(uaddr) && uaddr >= USER_VADDR_BOTTOM)
    return;
  thread_panic();
}

static void *
map_kaddr(const void *uaddr)
{
  void *ptr = pagedir_get_page(thread_current()->pagedir, uaddr);
  if (!ptr)
  {
    thread_panic();
  }
  return ptr;
}

static int check_user_str(const char *uaddr)
{
  int len = 0;
  for (const char *p = uaddr;; p++)
  {
    check_uaddr(p);
    const char *q = map_kaddr(p);
    if (*q == '\0')
      break;
    len++;
  }
  return len;
}

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void fetch_args(struct intr_frame *f, int32_t *args, int n)
{
  int32_t *ptr;
  for (int i = 0; i < n; i++)
  {
    ptr = ((int32_t *)(f->esp)) + i + 1;
    check_uaddr(ptr);
    args[i] = *(int *)map_kaddr(f->esp + sizeof(int32_t) * (i + 1));
  }
}

static void syscall_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  thread_current()->state->exit_code = args[0];
  thread_exit();
}

static void syscall_exec(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  const char *cmd_line = (const char *)args[0];
  check_user_str(cmd_line);
  f->eax = process_execute(cmd_line);
}

static void syscall_wait(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  tid_t tid = (tid_t)args[0];
  f->eax = process_wait(tid);
}

static void syscall_create(struct intr_frame *f UNUSED)
{
  int32_t args[2];
  fetch_args(f, args, 2);
  const char *file = (const char *)args[0];
  unsigned initial_size = (unsigned)args[1];
  check_user_str(file);
  lock_acquire(&filesys_lock);
  f->eax = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
}

static void syscall_remove(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  const char *file = (const char *)args[0];
  check_user_str(file);
  lock_acquire(&filesys_lock);
  f->eax = filesys_remove(file);
  lock_release(&filesys_lock);
}

static void syscall_open(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  const char *file = (const char *)args[0];
  check_user_str(file);
  lock_acquire(&filesys_lock);
  struct file *file_ptr = filesys_open(file);
  lock_release(&filesys_lock);
  if (!file_ptr)
  {
    f->eax = -1;
    return;
  }
  struct thread_open_file *open_file = malloc(sizeof(struct thread_open_file));
  if (!open_file)
  {
    lock_acquire(&filesys_lock);
    file_close(file_ptr);
    lock_release(&filesys_lock);
    f->eax = -1;
    return;
  }
  struct thread *cur = thread_current();
  open_file->file = file_ptr;
  lock_acquire(&cur->files_lock);
  open_file->fd = ++cur->max_fd;
  list_push_back(&cur->files, &open_file->elem);
  lock_release(&cur->files_lock);
  f->eax = open_file->fd;
}

/**
 * Get the open file struct
 * Caller should hold files_lock
 */
static struct thread_open_file *get_open_file(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e))
  {
    struct thread_open_file *open_file = list_entry(e, struct thread_open_file, elem);
    if (open_file->fd == fd)
    {
      return open_file;
    }
  }
  return NULL;
}

static void syscall_filesize(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  int fd = args[0];
  struct thread *cur = thread_current();
  lock_acquire(&cur->files_lock);
  struct thread_open_file *open_file = get_open_file(fd);
  lock_release(&cur->files_lock);
  if (!open_file)
  {
    f->eax = -1;
    return;
  }
  lock_acquire(&filesys_lock);
  f->eax = file_length(open_file->file);
  lock_release(&filesys_lock);
}

static void syscall_read(struct intr_frame *f UNUSED)
{
  int32_t args[3];
  fetch_args(f, args, 3);
  int fd = args[0];
  void *buffer = (void *)args[1];
  unsigned size = (unsigned)args[2];
  check_uaddr(buffer);
  map_kaddr(buffer);
  check_uaddr(buffer + size - 1);
  map_kaddr(buffer + size - 1);
  if (fd == 0)
  {
    for (unsigned i = 0; i < size; i++)
    {
      ((char *)buffer)[i] = input_getc();
    }
    f->eax = size;
  }
  else
  {
    struct thread *cur = thread_current();
    lock_acquire(&cur->files_lock);
    struct thread_open_file *open_file = get_open_file(fd);
    lock_release(&cur->files_lock);
    if (!open_file)
    {
      f->eax = -1;
      return;
    }
    lock_acquire(&filesys_lock);
    f->eax = file_read(open_file->file, buffer, size);
    lock_release(&filesys_lock);
  }
}

static void syscall_write(struct intr_frame *f UNUSED)
{
  int32_t args[3];
  fetch_args(f, args, 3);
  int fd = args[0];
  const void *buffer = (const void *)args[1];
  unsigned size = (unsigned)args[2];
  check_uaddr(buffer);
  map_kaddr(buffer);
  check_uaddr(buffer + size - 1);
  map_kaddr(buffer + size - 1);
  if (fd == 1)
  {
    putbuf(buffer, size);
    f->eax = size;
  }
  else
  {
    struct thread *cur = thread_current();
    lock_acquire(&cur->files_lock);
    struct thread_open_file *open_file = get_open_file(fd);
    lock_release(&cur->files_lock);
    if (!open_file)
    {
      f->eax = -1;
      return;
    }
    lock_acquire(&filesys_lock);
    f->eax = file_write(open_file->file, buffer, size);
    lock_release(&filesys_lock);
  }
}

static void syscall_seek(struct intr_frame *f UNUSED)
{
  int32_t args[2];
  fetch_args(f, args, 2);
  int fd = args[0];
  unsigned position = (unsigned)args[1];
  struct thread *cur = thread_current();
  lock_acquire(&cur->files_lock);
  struct thread_open_file *open_file = get_open_file(fd);
  lock_release(&cur->files_lock);
  if (!open_file)
  {
    return;
  }
  lock_acquire(&filesys_lock);
  file_seek(open_file->file, position);
  lock_release(&filesys_lock);
}

static void syscall_tell(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  int fd = args[0];
  struct thread *cur = thread_current();
  lock_acquire(&cur->files_lock);
  struct thread_open_file *open_file = get_open_file(fd);
  lock_release(&cur->files_lock);
  if (!open_file)
  {
    f->eax = -1;
    return;
  }
  lock_acquire(&filesys_lock);
  f->eax = file_tell(open_file->file);
  lock_release(&filesys_lock);
}

static void syscall_close(struct intr_frame *f UNUSED)
{
  int32_t args[1];
  fetch_args(f, args, 1);
  int fd = args[0];
  struct thread *cur = thread_current();
  lock_acquire(&cur->files_lock);
  struct thread_open_file *open_file = get_open_file(fd);
  if (open_file)
  {
    list_remove(&open_file->elem);
  }
  lock_release(&cur->files_lock);
  if (open_file)
  {
    lock_acquire(&filesys_lock);
    file_close(open_file->file);
    lock_release(&filesys_lock);
    free(open_file);
  }
}

// syscall table
static void (*syscall_table[])(struct intr_frame *) = {
    [SYS_HALT] = syscall_halt,
    [SYS_EXIT] = syscall_exit,
    [SYS_EXEC] = syscall_exec,
    [SYS_WAIT] = syscall_wait,
    [SYS_CREATE] = syscall_create,
    [SYS_REMOVE] = syscall_remove,
    [SYS_OPEN] = syscall_open,
    [SYS_FILESIZE] = syscall_filesize,
    [SYS_READ] = syscall_read,
    [SYS_WRITE] = syscall_write,
    [SYS_SEEK] = syscall_seek,
    [SYS_TELL] = syscall_tell,
    [SYS_CLOSE] = syscall_close,
};
static const int syscall_table_size = sizeof(syscall_table) / sizeof(syscall_table[0]);

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int32_t syscall_no = *(int32_t *)map_kaddr(f->esp);
  if (syscall_no < 0 || syscall_no >= syscall_table_size)
  {
    // printf("invalid syscall number: %d\n", syscall_no);
    thread_panic();
  }
  syscall_table[syscall_no](f);
}
