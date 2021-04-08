#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h" power_off




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

#define VALIDITY_CHECK(X) (!is_kernel_vaddr(X)) && (X != NULL) && is_user_vaddr(X)

void
syscall_init (void) {
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
		process_exit();
	else {
		uint64_t first_var = f->R.rdi; // copy to keep from TOCTOU attack
		uint64_t second_var = f->R.rsi; // copy to keep from TOCTOU attack
		uint64_t third_var = f->R.rdx; // copy to keep from TOCTOU attack
		if (!VALIDITY_CHECK(first_var)) process_exit(); // resource leak 처리함
		switch (f->R.rax)
		{
		case SYS_EXIT:
			exit(first_var);
			break;
		case SYS_FORK:
			f->R.rax = fork(first_var);
			break;
		case SYS_EXEC:
			f->R.rax = exec(first_var);
			break;
		case SYS_WAIT:
			f->R.rax = wait(first_var);
			break;
		case SYS_CREATE:
			if (!VALIDITY_CHECK(second_var)) process_exit();
			f->R.rax = create(first_var, second_var);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(first_var);
			break;
		case SYS_OPEN:
			f->R.rax = open(first_var);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(first_var);
			break;
		case SYS_READ:
			if (!VALIDITY_CHECK(second_var)) process_exit();
			if (!VALIDITY_CHECK(third_var)) process_exit();
			f->R.rax = read(first_var, second_var , third_var);
			break;
		case SYS_WRITE:
			if (!VALIDITY_CHECK(second_var)) process_exit();
			if (!VALIDITY_CHECK(third_var)) process_exit();
			f->R.rax = write(first_var, second_var , third_var);
			break;
		case SYS_SEEK:
			if (!VALIDITY_CHECK(second_var)) process_exit();
			seek(first_var, second_var);
			break;
		case SYS_TELL:
			f->R.rax = tell(first_var);
			break;
		case SYS_CLOSE:
			close (first_var);
			break;
		default:
			process_exit();
			break;
		}
	}
	
	

	// handle


	printf ("system call!\n");
	thread_exit ();
}



/*
 * our code: 구현 system call
 */
//halt
void halt (void) {
	power_off();
}

void exit (int status){

	if(parent wait) return status to the kernel
}

pid_t fork (const char *thread_name){
	duplicate_pte (uint64_t *pte, void *va, void *aux)
	// Clone %RBX, %RSP, %RBP, and %R12 - %R15

	return pid of child
}
int exec (const char *file){
	
}
int wait (pid_t){
	if(pid not die) wait until fid terminate;
}


