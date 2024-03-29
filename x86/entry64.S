/* SPDX-License-Identifier: BSD-2-Clause */
/*-
 * Copyright (c) 2016 Martin Lucina.  All Rights Reserved.
 *
 * Based on rumprun/hw arch/amd64/locore.S, which is:
 * Copyright (c) 2014, 2015 Antti Kantee.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* necessary for CONFIG_ macros to be accessible */
#include <uk/config.h>

#include <uk/arch/limits.h>
#include <x86/cpu_defs.h>
#include <hyperv-x86/traps.h>
#ifndef CONFIG_UKPLAT_HAVE_MULTIBOOT2
#include <hyperv-x86/multiboot_defs.h>
#else
#include <hyperv-x86/multiboot2_defs.h>
#endif /* CONFIG_UKPLAT_HAVE_MULTIBOOT2 */

#define ENTRY(x) .globl x; .type x,%function; x:
#define END(x)   .size x, . - x

#ifndef CONFIG_UKPLAT_HAVE_MULTIBOOT2
#define MYMULTIBOOT_FLAGS \
    (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_AOUT_KLUDGE)
#else
#define AOUT_KLUDGE MULTIBOOT_AOUT_KLUDGE
#endif /* CONFIG_UKPLAT_HAVE_MULTIBOOT2 */

.section .data.boot

.align 4
#ifndef CONFIG_UKPLAT_HAVE_MULTIBOOT2
_multiboot_header:
.long MULTIBOOT_HEADER_MAGIC
.long MYMULTIBOOT_FLAGS
.long -(MULTIBOOT_HEADER_MAGIC+MYMULTIBOOT_FLAGS) /* checksum */
.long _multiboot_header                           /* header addr */
.long 0x100000                                    /* load addr */
.long _edata                                      /* load end addr */
.long _end                                        /* bss end addr */
.long _libhypervplat_start32                         /* entry addr */
#else
_multiboot_header:
        /*  magic */
        .long   MULTIBOOT2_HEADER_MAGIC
        /*  ISA: i386 */
        .long   MULTIBOOT_ARCHITECTURE_I386
        /*  Header length. */
        .long   multiboot_header_end - _multiboot_header
        /*  checksum */
        .long   -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT_ARCHITECTURE_I386 + (multiboot_header_end - _multiboot_header))
.align 8
address_tag_start:
        .short MULTIBOOT_HEADER_TAG_ADDRESS
        .short MULTIBOOT_HEADER_TAG_OPTIONAL
        .long address_tag_end - address_tag_start
        /*  header_addr */
        .long   _multiboot_header
        /*  load_addr */
        .long   _text
        /*  load_end_addr */
        .long   _edata
        /*  bss_end_addr */
        .long   _end
address_tag_end:
.align 8
entry_address_tag_start:
        .short MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS
        .short MULTIBOOT_HEADER_TAG_OPTIONAL
        .long entry_address_tag_end - entry_address_tag_start
        /*  entry_addr */
        .long _libhypervplat_start32
entry_address_tag_end:
.align 8
information_request_tag_start:
		.short MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST
		.short MULTIBOOT_HEADER_TAG_OPTIONAL
		.long information_request_tag_end - information_request_tag_start
		/* command line */
		.long 1
information_request_tag_end:
multiboot_header_end:
#endif /* CONFIG_UKPLAT_HAVE_MULTIBOOT2 */

.section .bss

.space 4096
bootstack:

/*
 * Bootloader entry point.
 *
 * Bootstrap is slightly different from i386.  Multiboot puts us only
 * in 32bit mode, so it's our responsibility to install a page table
 * and switch to long mode.  Notably, we can't call C code until
 * we've switched to long mode.
 */
.code32
.section .text.boot

ENTRY(_libhypervplat_start32)
	cld

	/* only multiboot is supported for now */
#ifndef CONFIG_UKPLAT_HAVE_MULTIBOOT2
	cmpl $MULTIBOOT_BOOTLOADER_MAGIC, %eax
#else
	cmpl $MULTIBOOT2_BOOTLOADER_MAGIC, %eax
#endif /* CONFIG_UKPLAT_HAVE_MULTIBOOT2 */
	jne nomultiboot

have_multiboot:
	/*
	 * Multiboot drops us off in 32-bit protected mode with some sane
	 * initial settings, good enough to go straight for the only thing
	 * that we care about: go straight into long mode..
	 */

	/* 1: enable pae */
	movl %cr4, %eax
	orl $X86_CR4_PAE, %eax
	movl %eax, %cr4

	/* 2: enable long mode */
	movl $0xc0000080, %ecx
	rdmsr
	orl $X86_EFER_LME, %eax
	orl $X86_EFER_NXE, %eax
	wrmsr

	/* 3: load pml4 pointer */
	movl $cpu_pml4, %eax
	movl %eax, %cr3

	/* 4: enable paging */
	movl %cr0, %eax
	orl $X86_CR0_PG, %eax
	movl %eax, %cr0

	jmp _libhypervplat_start64

	/* NOTREACHED */
	jmp haltme

nomultiboot:

haltme:
	cli
	hlt
	jmp haltme
END(_libhypervplat_start32)

/*
 * amd64 programmer's manual:
 *
 * "In long mode, segmentation is not used ... except for a few exceptions."
 *
 * Uuuyea, exceptions.
 */

.section .data.boot
.align 64
gdt64:
	.quad 0x0000000000000000
gdt64_cs:
	.quad GDT_DESC_CODE_VAL		/* 64bit CS		*/
gdt64_ds:
	.quad GDT_DESC_DATA_VAL		/* DS			*/
	.quad 0x0000000000000000	/* TSS part 1 (via C)	*/
	.quad 0x0000000000000000	/* TSS part 2 (via C)	*/
gdt64_end:
.align 64

.type gdt64_ptr, @object
gdt64_ptr:
	.word gdt64_end-gdt64-1
	.quad gdt64

.type mxcsr_ptr, @object
mxcsr_ptr:
	.long 0x1f80			/* Intel SDM power-on default */


#include "pagetable.S"

.code64
.section .text.boot

ENTRY(_libhypervplat_start64)
	/* set up the boot stack */
	movq $bootstack, %rsp
	xorq %rbp, %rbp

	lgdt (gdt64_ptr)
	/* let lret jump just one instruction ahead, but set %cs
	 * to the correect GDT entry while doing that.
	 */
	pushq $(gdt64_cs-gdt64)
	pushq $1f
	lretq
1:
	/* Set up the remaining segment registers */
	movq $(gdt64_ds-gdt64), %rax
	movq %rax, %ds
	movq %rax, %es
	movq %rax, %ss
	xorq %rax, %rax
	movq %rax, %fs
	movq %rax, %gs

	/* Multiboot gives us a pointer to its mutliboot information in ebx.
	 * However, we need that for cpuid, so push it here and then
	 * and pop it back at the end.
	 */
	pushq %rbx

	/* We will work on cr0 and cr4 multiple times.
	 * We put cr0 into rsi and cr4 into rdi, because cpuid and
	 * xgetbv/xsetbv work on eax/ebx/ecx/edx. */
	movq %cr0, %rsi
	movq %cr4, %rdi
	/* FPU and SSE are part of base x86-64, so no need to check for their
	 * availability before enabling and initializing. */
	andl $(~(X86_CR0_EM | X86_CR0_TS)), %esi
	orl $(X86_CR0_MP | X86_CR0_NE | X86_CR0_WP), %esi
	movq %rsi, %cr0
	fninit
#if __SSE__
	orl $(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT), %edi
	movq %rdi, %cr4
	ldmxcsr (mxcsr_ptr)
#endif /* __SSE__ */
#if (__AVX__ || CONFIG_HAVE_X86PKU)
	/* Check capabilities subject to availability as indicated by cpuid.
	 * First, start off with "standard features" */
	movl $0x1, %eax
	cpuid
	/* ecx and edx now contain capability information, so we can now
	 * enable capabilities based on the indicated features */
	/* note: OSXSAVE needs to be enabled before AVX and PKU */
	testl $(X86_CPUID1_ECX_XSAVE), %ecx
	jz noxsave
	orl $(X86_CR4_OSXSAVE), %edi
	movq %rdi, %cr4
#if __AVX__
	/* now enable AVX. This needs to be last checking cpuid features from
	 * the eax=1 cpuid call, because it clobbers ecx */
	testl $(X86_CPUID1_ECX_AVX), %ecx
	jz noavx
	xorl %ecx, %ecx
	xgetbv
	orl $(X86_XCR0_SSE | X86_XCR0_AVX), %eax
	xsetbv
noavx:
#endif /* __AVX__ */
/* Do not enable AVX without XSAVE, otherwise we'll get #UD */
noxsave:
#endif /* __AVX__ || CONFIG_HAVE_X86PKU */
	/* Now, check for extended features. */
	movl $0x7, %eax
	movl $0x0, %ecx
	cpuid
	/* ebx, ecx, edx now contain extended capabilities information. */
	/* check for and enable FS/GSBASE */
	testl $(X86_CPUID7_EBX_FSGSBASE), %ebx
	jz nofsgsbase
	orl $(X86_CR4_FSGSBASE), %edi
	movq %rdi, %cr4
nofsgsbase:
#if CONFIG_HAVE_X86PKU
	/* check for Memory Protection Keys (PKU) */
	testl $(X86_CPUID7_ECX_PKU), %ecx
	jz nopku
	/* only enable PKU if we support XSAVE */
	testl $(X86_CR4_OSXSAVE), %edi
	jz nopku
	/* PKU is supported, enable it via CR4 */
	orl $(X86_CR4_PKE), %edi
	movq %rdi, %cr4
	/* also enable XSAVE for the PKRU */
	xorl %ecx, %ecx
	xgetbv
	orl $(X86_XCR0_PKRU), %eax
	xsetbv
nopku:
#endif /* CONFIG_HAVE_X86PKU */
	/* done setting up CPU capabilities */

	/* read multiboot info pointer */
	popq %rdi

	call _libhypervplat_entry

	cli
	hlt
END(_libhypervplat_start64)

.text
ENTRY(_libhypervplat_newstack)
	movq %rdi, %rsp
	movq %rdx, %rdi

	pushq $0x0
	pushq $0x0

	call *%rsi

	cli
	hlt
END(_libhypervplat_newstack)

.globl hypercall_page
        .align __PAGE_SIZE
hypercall_page:
        .fill __PAGE_SIZE,1,0

.globl hyperv_message_page
        .align __PAGE_SIZE
hyperv_message_page:
        .fill __PAGE_SIZE,1,0

.globl hyperv_event_flags_page
        .align __PAGE_SIZE
hyperv_event_flags_page:
        .fill __PAGE_SIZE,1,0
