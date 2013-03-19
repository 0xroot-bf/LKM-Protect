#include <asm/unistd.h> 
#include <linux/kernel.h> 
#include <linux/kmod.h> 
#include <linux/mm.h> 
#include <linux/module.h> 
#include <linux/string.h> 
#include <linux/syscalls.h>
#include <linux/types.h> 

#define KEY	1337
#define SIGNAL 	31
#define ON	0x01
#define OFF	0x00

unsigned long * syscall_table();

asmlinkage int (*syscall_init_module) (const char *ModuleName, struct module *ModuleStruct);
asmlinkage int (*syscall_delete_module) (const char *ModuleName);
asmlinkage int (*syscall_kill) (pid_t pid, int sig);

struct {
	int iKey;
	int iSig;
	int iMperm;
} status;

// 	Get the sys_call_table address
unsigned long* syscall_table() {
	unsigned long *swi_address = 0xFFFF0008;
	unsigned long vector_swi_offset = 0;
	unsigned long vector_swi_instruction = 0;
	unsigned long *vector_swi_pointer = NULL;
	unsigned long *ptr = NULL;
	unsigned long *syscall = NULL;
    unsigned long syscall_table_offset = 0;

	memcpy(&vector_swi_instruction, swi_address, sizeof(vector_swi_instruction));
	printk(KERN_INFO "--->DEBUG: Vector SWI Instruction: %lx\n", vector_swi_instruction);

	vector_swi_offset = vector_swi_instruction & (unsigned long)0x00000FFF;
	printk(KERN_INFO "--->DEBUG: Vector SWI Offset: 0x%lx\n", vector_swi_offset);

	vector_swi_pointer = (unsigned long *)((unsigned long)swi_address+vector_swi_offset+8);
	printk(KERN_INFO "--->DEBUG: Vector SWI Address Pointer %p, Value: %lx\n", vector_swi_pointer, *vector_swi_pointer);

	ptr = *vector_swi_pointer;
	
	while(syscall == NULL) {
		if((*ptr & (unsigned long)0xFFFFFF000) == 0xE28F8000) {
			syscall_table_offset = *ptr & (unsigned long)0x00000FFF;
			syscall = (unsigned long)ptr+8+syscall_table_offset;
			printk(KERN_INFO "--->DEBUG: Syscall Table Found at %p\n", syscall);
			break;
		}
		ptr++;
	}
	return syscall;
}

asmlinkage ssize_t hooked_init_module (const char *ModuleName, struct module *ModuleStruct) {
	return (-1);		// WRONGGG WRONNNNG INTRUDER
}

asmlinkage ssize_t hooked_delete_module (const char *ModuleName) {
	return (-1);
}

asmlinkage ssize_t hooked_kill (pid_t pid, int sig) {
	unsigned long *syscall = syscall_table();

	if(sig != status.iSig) return ((*syscall_kill)(pid, sig));
	if(pid == status.iKey) {
		if(status.iMperm == OFF) {
			status.iMperm = ON;
			syscall[__NR_init_module] = syscall_init_module;
			syscall[__NR_delete_module] = syscall_delete_module;
		}
		else {
			status.iMperm = OFF;
			syscall[__NR_init_module] = hooked_init_module;
			syscall[__NR_delete_module] = hooked_delete_module;
		}
	}

	return 0;
}

// Our initial module
static int __init secure_kernel() {
	printk(KERN_INFO "---> Loading Module\n");
	printk(KERN_INFO "---> Done.\n");

	unsigned long *syscall = syscall_table();

	status.iMperm = OFF;
	status.iKey = KEY;
	status.iSig = SIGNAL;

	// Hook syscalls
	syscall_init_module = syscall[__NR_init_module];
	syscall[__NR_init_module] = hooked_init_module;

	syscall_delete_module = syscall[__NR_delete_module];
	syscall[__NR_delete_module] = hooked_delete_module;

	syscall_kill = syscall[__NR_kill];
	syscall[__NR_kill] = hooked_kill;

	return 0;
}

// Our delete module
static int __exit unsecure_kernel() {
	printk(KERN_INFO "---> (Stop) Getting syscall_table\n");
	unsigned long *syscall = syscall_table();

	printk(KERN_INFO "---> (Stop) Restoring original syscalls\n");
	syscall[__NR_init_module] = syscall_init_module;
	syscall[__NR_delete_module] = syscall_delete_module;
	syscall[__NR_kill] = syscall_kill;

}

module_init	(secure_kernel);
module_exit (unsecure_kernel);