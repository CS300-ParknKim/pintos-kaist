#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
// #include "unistd.h" //채점시 필히 수정
#include "threads/synch.h"
#include <lib/stdio.h>
#include <kernel/stdio.h>
#include "kernel/list.h"
#include "threads/malloc.h"
#include "filesys/inode.h"

#include "vm/vm.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

//#define VALIDITY_CHECK(X) (!is_kernel_vaddr(X)) && (X != NULL) && is_user_vaddr(X)

// The kernel must be very careful about doing so, 
// because the user can pass a null pointer, 
// a pointer to unmapped virtual memory, 
// or a pointer to kernel virtual address space (above KERN_BASE).
void valid_check(const void* x){
	// if (x == NULL)
	// 	exit(-1);
	// if (pml4_get_page(thread_current()->pml4, x) != NULL)
	// 	exit(-1);
	if (is_kernel_vaddr(x))
		exit(-1);
	// bool b1 = (!is_kernel_vaddr(x));
	// bool b2 = (x != NULL);
	// void* ret_val = pml4_get_page(thread_current()->pml4, x);//Why NULL?
	// bool b3 = (ret_val == NULL);
	// if(!b1 || !b2 || b3)
	// 	printf("kervel vaddr? %d NULL? %d unmmaped %d\n", b1,b2, b3);
	// return b1 && b2 && !b3;
}

struct lock file_lock;

// make file_s
struct file_s *init_file_s(struct file *f, int fd){
	struct file_s *new_one = (struct file_s *) malloc(sizeof(struct file_s));
	new_one->file = f;
	new_one->fd = fd;

	return new_one;
}

//fd있으면 file 찾아줌
struct file *
find_file (int find_fd, struct list *fd_table) {

	if(find_fd < 0) return NULL;
	struct list_elem *e;
	e = list_begin(fd_table);
	while (e != list_end(fd_table)) {
		// printf(" .");
		int e_fd = list_entry(e, struct file_s, fd_elem) -> fd;
		if (e_fd == find_fd)
			return list_entry(e, struct file_s, fd_elem) -> file;
		e = list_next(e);
	}
	return NULL;
}

struct file_s *
find_file_s (int find_fd, struct list *fd_table) {
	if(find_fd < 0) return NULL;
	struct list_elem *e;
	e = list_begin(fd_table);
	while (e != list_end(fd_table)) {
		int e_fd = list_entry(e, struct file_s, fd_elem) -> fd;
		if (e_fd == find_fd)
			return list_entry(e, struct file_s, fd_elem);
		e = list_next(e);
	}
	return NULL;
}


void
syscall_init (void) {
	// our code: init file_lock
	lock_init (&file_lock);
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface 
 * syscall.h : For user program only
 * system call number : %rax, 
 * arguments : %rdi, %rsi, %rdx, %r10, %r8, and %r9. 
 * *f는 kernel stack
 * return은 f->rax에 저장
 * <교수님 예시코드>
 * 	int sys_num = f->R.rax;
	//if(sys_num means read)
	int fd = f->R.rdi;
 * 구현 후에는 panic assertion 절대 안떠야함
 * Invalid argument 들어오면 error value return 또는 terminating.	
 * 
 * open (*a)    a -> userprogram_file
 * return value: rax
 * argument a: R.rdi
 * 
 * Q. write("buf") -> buf is copied
*/
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	// check validity of user pointer
	// mmu.c와 threads/vaddr.h 참고 is_kernel_vaddr(vaddr)
	//null pointer/unmapped virtual memory/pointer to kernel virtual address space (above KERN_BASE)
	if (f->R.rax == SYS_HALT)
		halt();
	else {
		uint64_t first_var = f->R.rdi; // copy to keep from TOCTOU attack
		uint64_t second_var = f->R.rsi; // copy to keep from TOCTOU attack
		uint64_t third_var = f->R.rdx; // copy to keep from TOCTOU attack

		valid_check(first_var);
			
		switch (f->R.rax)
		{
		case SYS_EXIT:
			exit(first_var);
			break;
		case SYS_FORK:
			thread_current()->for_fork_if = f;
			f->R.rax = fork(first_var);
			break;
		case SYS_EXEC:
			f->R.rax = exec(first_var);
			break;
		case SYS_WAIT:
			f->R.rax = wait(first_var);
			break;
		case SYS_CREATE:
			// if (!valid_check(second_var)) exit(-1);
			valid_check(second_var);
			f->R.rax = create(first_var, second_var);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(first_var);
			break;
		case SYS_OPEN:
			// return이  없을때는?
			f->R.rax = open(first_var);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(first_var);
			break;
		case SYS_READ:
			valid_check(second_var);
			valid_check(third_var);
			f->R.rax = read(first_var, second_var , third_var);
			break;
		case SYS_WRITE:
			valid_check(second_var);
			valid_check(third_var);
			f->R.rax = write(first_var, second_var, third_var);
			break;
		case SYS_SEEK:
			valid_check(second_var);
			seek(first_var, second_var);
			break;
		case SYS_TELL:
			f->R.rax = tell(first_var);
			break;
		case SYS_CLOSE:
			close (first_var);
			break;
		default:
			thread_exit();
			break;
		}
	}
	
}



/*
 * our code: 구현 system call
 */
void halt (void) {
	printf("halt\n");
	power_off();
}

void exit (int status){
	struct thread *curr = thread_current();
	printf ("%s: exit(%d)\n", thread_name (), status);
	curr->exit_status = status;

	
	// for (struct list_elem *e = list_begin(&curr->child_list);
	// 	e != list_end(&curr->child_list); e = list_next(e)) {
	// 	struct thread *t = list_entry(e, struct thread, child_elem);
	// 	wait(t->tid);
	// }

	thread_exit(); // process_exit 호출
}


pid_t fork (const char *thread_name){

	struct thread *curr = thread_current();




	int depth_count = 0;
	struct thread *parent = curr -> parent_thread;
	while (parent != NULL) {
		depth_count++;
		parent = parent -> parent_thread;
	}
	if (depth_count > 30) exit(depth_count);





	tid_t child_pid = process_fork(thread_name, curr->for_fork_if);

	// if child fork worked well, then lock release
	sema_down(&curr->fork_sema);
	
	return child_pid;
	// parent : child 복제 끝난 후 child pid 받음. 실패시 TID_ERROR
	// child : 언제든 0 return 받음
}

int exec (const char *cmd_line) {
	char *fn_copy;

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, cmd_line, PGSIZE);
	
	int ret = process_exec(fn_copy);



	// struct thread *current = thread_current();
	// struct thread *parent = current->parent_thread;

	// struct list_elem *e = list_begin(&parent->fd_table);
	
	// // 나중에 좀 고쳐지면 file lock 추가
	// printf("parent fd table:\n");
	// while(e != list_end(&parent->fd_table)){
	// 	//same pos, repone parent inode, deny write
	// 	struct file_s *parent_f_s = list_entry(e, struct file_s, fd_elem);
	// 	printf("%d", parent_f_s->fd);
	// 	printf("\n");

	// 	e = list_next(e);
	// }

	// printf("\ncurrent fd table:\n");

	// while(e != list_end(&parent->fd_table)){
	// 	//same pos, repone parent inode, deny write
	// 	struct file_s *current_f_s = list_entry(e, struct file_s, fd_elem);
	// 	printf("%d", current_f_s->fd);
	// 	printf("\n");

	// 	e = list_next(e);
	// }


	return ret;
}

int wait (pid_t pid){
//	printf("wait\n");
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
//	printf("create\n");
	if(file == NULL) exit(-1);

	lock_acquire(&file_lock);
	bool crfile = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return crfile;
}

bool remove (const char *file) {
//	printf("remove\n");
	lock_acquire(&file_lock);
	bool rmfile = filesys_remove (file);
	lock_release(&file_lock);
	return rmfile;
}

// Extra 구현시 open 수정
// 
int open (const char *file) {
//	printf("open\n");

	if(file == NULL) exit(-1);
	
	lock_acquire(&file_lock);
	struct file *opened_file = filesys_open(file);
	
	if(opened_file == NULL) {
		lock_release(&file_lock);
		return -1;
	} else {
		struct thread *curr = thread_current();
		curr->next_fd++;
		struct file_s *new = init_file_s(opened_file, curr->next_fd); //opened_file 대신 file 써서 틀림.. 변수 이름을 잘짓자
		list_push_back(&curr->fd_table, &new->fd_elem);

		//if (file = curr->name) file_deny_write(new->file);

		lock_release(&file_lock);
		return curr->next_fd;
	}

}

int filesize (int fd) {
//	printf("filesize\n");
	
	lock_acquire(&file_lock);
	
	int size;

	struct thread *curr = thread_current();
	struct file *f = find_file(fd, &curr->fd_table);
	if(f == NULL) size = -1; // invlaid fd
	else size = file_length(f);
	
	lock_release(&file_lock);

	return size;
}

int read (int fd, void *buffer, unsigned size) {
//	printf("read\n");
	lock_acquire(&file_lock);

	int read_bytes;

	if (fd == STDIN_FILENO) read_bytes = input_getc();
	else {
		struct thread *curr = thread_current();
		struct file *f = find_file(fd, &curr->fd_table);
		if(f == NULL) read_bytes = -1;
		else read_bytes = file_read(f, buffer, size);
	}

	lock_release(&file_lock);

	return read_bytes;
}

// Read-Only file 어떻게 하나
int write (int fd, const void *buffer, unsigned size){
	if(buffer == NULL) exit(-1);

	lock_acquire(&file_lock);

	int write_bytes;
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		write_bytes = size;
	}  
	else{
		struct thread *curr = thread_current();
		struct file *f = find_file(fd, &curr->fd_table);

		if(f == NULL) write_bytes = -1;
		else{
			// if (f->inode == curr->exec_file->inode &&
			// 	f->deny_write == false)
			// 	file_deny_write(f);
			write_bytes = file_write(f, buffer, (off_t)size);//fd2, 0x604d60, 373
		}

	}
	
	lock_release(&file_lock);
	// printf("write_bytes: %d\n", write_bytes);
	return write_bytes;
}

void seek (int fd, unsigned position) {
	lock_acquire(&file_lock);

	struct thread *curr = thread_current();
	struct file* f = find_file(fd, &curr->fd_table);
	//STDIN, STDOUT같은 경우는 아마 console이라 고려 대상 X
	// file 끝 넘겨도 됨. 그냥 다음 read call시 0만 돌려줌
	if (f != NULL) file_seek(f, position);

	lock_release(&file_lock);
}

unsigned tell (int fd) {
	lock_acquire(&file_lock);
	int ret;
	struct file *f = find_file(fd, &thread_current()->fd_table) ;
	if (f != NULL) ret = file_tell(f);
	lock_release(&file_lock);

	return ret;
}

// 프로세스 종료시 다 닫혀야함
// close end, exit(0) 출력 안됨.
void close (int fd){
	lock_acquire(&file_lock);

	struct thread *curr = thread_current();
	struct file_s *f_s = find_file_s(fd, &curr->fd_table);
	if (f_s != NULL) {
		file_close(f_s->file);
		list_remove(&f_s->fd_elem);
	}
	lock_release(&file_lock);
}



/*
 * synchronize system calls so that any number of user processes can make them at once. 
 * It is not safe to call into the file system code provided in the filesys directory from multiple threads at once. 
 * Your system call implementation must treat the file system code as a critical section. 
 * Don't forget that process_exec() also accesses files. 
 * filesys directory 수정 x
 * user-level function for each system call : lib/user/syscall.c. 
 * These provide a way for user processes to invoke each system call from a C program. 
 * Each uses a little inline assembly code to invoke the system call and (if appropriate) returns the system call's return value
*/






















