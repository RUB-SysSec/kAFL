#ifndef KAFL_USER_H
#define KAFL_USER_H

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else 
#include <stdint.h>
#endif

#define HYPERCALL_KAFL_RAX_ID			0x01f
#define HYPERCALL_KAFL_ACQUIRE			0
#define HYPERCALL_KAFL_GET_PAYLOAD		1
#define HYPERCALL_KAFL_GET_PROGRAM		2
#define HYPERCALL_KAFL_GET_ARGV			3
#define HYPERCALL_KAFL_RELEASE			4
#define HYPERCALL_KAFL_SUBMIT_CR3		5
#define HYPERCALL_KAFL_SUBMIT_PANIC		6
#define HYPERCALL_KAFL_SUBMIT_KASAN		7
#define HYPERCALL_KAFL_PANIC			8
#define HYPERCALL_KAFL_KASAN			9
#define HYPERCALL_KAFL_LOCK				10
#define HYPERCALL_KAFL_INFO				11
#define HYPERCALL_KAFL_NEXT_PAYLOAD		12

#define PAYLOAD_SIZE					(128 << 10)				/* up to 128KB payloads */
#define PROGRAM_SIZE					(16  << 20)				/* kAFL supports 16MB programm data */
#define INFO_SIZE                       (128 << 10)				/* 128KB info string */
#define TARGET_FILE						"/tmp/fuzzing_engine"	/* default target for the userspace component */
#define TARGET_FILE_WIN					"fuzzing_engine.exe"	

typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-4];
} kAFL_payload;

static inline void kAFL_hypercall(uint64_t rbx, uint64_t rcx){
	uint64_t rax = HYPERCALL_KAFL_RAX_ID;
	asm ("movq %0, %%rcx;" : : "r"(rcx));
	asm ("movq %0, %%rbx;" : : "r"(rbx));
    asm ("movq %0, %%rax;" : : "r"(rax));
    asm ("vmcall");
}

#endif