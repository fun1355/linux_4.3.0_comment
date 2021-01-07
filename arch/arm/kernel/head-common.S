/*
 *  linux/arch/arm/kernel/head-common.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <asm/assembler.h>

#define ATAG_CORE 0x54410001
#define ATAG_CORE_SIZE ((2*4 + 3*4) >> 2)
#define ATAG_CORE_SIZE_EMPTY ((2*4) >> 2)

#ifdef CONFIG_CPU_BIG_ENDIAN
#define OF_DT_MAGIC 0xd00dfeed
#else
#define OF_DT_MAGIC 0xedfe0dd0 /* 0xd00dfeed in big-endian */
#endif

/*
 * Exception handling.  Something went wrong and we can't proceed.  We
 * ought to tell the user, but since we don't have any guarantee that
 * we're even running on the right architecture, we do virtually nothing.
 *
 * If CONFIG_DEBUG_LL is set we try to print out something about the error
 * and hope for the best (useful if bootloader fails to pass a proper
 * machine ID for example).
 */
	__HEAD

/* Determine validity of the r2 atags pointer.  The heuristic requires
 * that the pointer be aligned, in the first 16k of physical RAM and
 * that the ATAG_CORE marker is first and present.  If CONFIG_OF_FLATTREE
 * is selected, then it will also accept a dtb pointer.  Future revisions
 * of this function may be more lenient with the physical address and
 * may also be able to move the ATAGS block if necessary.
 *
 * Returns:
 *  r2 either valid atags pointer, valid dtb pointer, or zero
 *  r5, r6 corrupted
 */
/**
 * 检查BOOT传入的ATAGS是否合法，ATAGS被BOOT中的setup_start_tag函数设置。
 */
__vet_atags:
/**
 * 检查atags是否四字节对齐，不对齐的话直接返回错误
 */
	tst	r2, #0x3			@ aligned?
	bne	1f

/**
 * 读入其长度，如果其长度不等于ATAG_CORE_SIZE，表示存储的内容不是ATAG
 */
	ldr	r5, [r2, #0]
#ifdef CONFIG_OF_FLATTREE
	ldr	r6, =OF_DT_MAGIC		@ is it a DTB?
	cmp	r5, r6
	beq	2f
#endif
	cmp	r5, #ATAG_CORE_SIZE		@ is first tag ATAG_CORE?
	cmpne	r5, #ATAG_CORE_SIZE_EMPTY
	bne	1f
/**
 * 判断其标志是否是ATAG_CORE，第一个元素必须是此类型
 */
	ldr	r5, [r2, #4]
	ldr	r6, =ATAG_CORE
	cmp	r5, r6
	bne	1f

2:	ret	lr				@ atag/dtb pointer is ok

1:	mov	r2, #0
	ret	lr
ENDPROC(__vet_atags)

/*
 * The following fragment of code is executed with the MMU on in MMU mode,
 * and uses absolute addresses; this is not position independent.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags/dtb pointer
 *  r9  = processor ID
 */
	__INIT
/**
 * 从这里开始，代码运行在MMU地址空间中。以绝对地址的方式执行，不必用PIC方式执行了。
 * 为start_kernel准备C运行环境。
 */
__mmap_switched:
/**
 * 计算PC相对于__mmap_switched_data地址的差异，计算PC减去相对地址的结果。
 * 这里可以不用这种PIC的方式，但是这样做应该可以节约一条指令。
 */
	adr	r3, __mmap_switched_data

/**
 * 从__mmap_switched_data加载__data_loc，_data，__bss_start，__end变量到寄存器中
 */
	ldmia	r3!, {r4, r5, r6, r7}
/**
 * __data_loc指向二进制文件中初始化数据的起始位置，__data指向内存中初始化数据的起始位置
 * 二者一般相等，也许XIP方式下二者会不相等。
 */
	cmp	r4, r5				@ Copy data segment if needed
/**
 * _data，__bss_start二者之间即为初始化数据，遍历复制它
 */
1:	cmpne	r5, r6
	ldrne	fp, [r4], #4
	strne	fp, [r5], #4
	bne	1b

/**
 * 清空BSS段
 */
	mov	fp, #0				@ Clear BSS (and zero fp)
1:	cmp	r6, r7
	strcc	fp, [r6],#4
	bcc	1b

/**
 * 前面的ldmia指令加了！，因此此时r3已经指向processor_id字段
 * 注意这里将init进程的SP指针读入到SP寄存器了。
 */
 ARM(	ldmia	r3, {r4, r5, r6, r7, sp})
 THUMB(	ldmia	r3, {r4, r5, r6, r7}	)
 THUMB(	ldr	sp, [r3, #16]		)
 /**
  * 存储处理器ID到全局processor_id变量中
  */
	str	r9, [r4]			@ Save processor ID
/**
 * 存储机器类型到__machine_arch_type字段
 */
	str	r1, [r5]			@ Save machine type
/**
 * 存储atags指针
 */
	str	r2, [r6]			@ Save atags pointer
	cmp	r7, #0
	strne	r0, [r7]			@ Save control register values
/**
 * 跳转到C运行环境，是不是想深呼吸一下:)
 */
	b	start_kernel
ENDPROC(__mmap_switched)

	.align	2
	.type	__mmap_switched_data, %object
__mmap_switched_data:
	.long	__data_loc			@ r4
	.long	_sdata				@ r5
	.long	__bss_start			@ r6
	.long	_end				@ r7
	.long	processor_id			@ r4
	.long	__machine_arch_type		@ r5
	.long	__atags_pointer			@ r6
#ifdef CONFIG_CPU_CP15
	.long	cr_alignment			@ r7
#else
	.long	0				@ r7
#endif
	.long	init_thread_union + THREAD_START_SP @ sp
	.size	__mmap_switched_data, . - __mmap_switched_data

/*
 * This provides a C-API version of __lookup_processor_type
 */
ENTRY(lookup_processor_type)
	stmfd	sp!, {r4 - r6, r9, lr}
	mov	r9, r0
	bl	__lookup_processor_type
	mov	r0, r5
	ldmfd	sp!, {r4 - r6, r9, pc}
ENDPROC(lookup_processor_type)

	__FINIT
	.text

/*
 * Read processor ID register (CP#15, CR0), and look up in the linker-built
 * supported processor list.  Note that we can't use the absolute addresses
 * for the __proc_info lists since we aren't running with the MMU on
 * (and therefore, we are not in the correct address space).  We have to
 * calculate the offset.
 *
 *	r9 = cpuid
 * Returns:
 *	r3, r4, r6 corrupted
 *	r5 = proc_info pointer in physical address space
 *	r9 = cpuid (preserved)
 */
/**
 * 查找处理器类型，在汇编语言中直接调用
 * 在r9中保存的是CPUID
 */
__lookup_processor_type:
/**
 * 加载procinfo起始地址到r3中
 */
	adr	r3, __lookup_processor_type_data
/**
 * 将proc info加载到临时寄存器中
 */
	ldmia	r3, {r4 - r6}	@ r4-r6中保存的是物理地址
/**
 * 计算物理地址和虚拟之间的差异
 */
	sub	r3, r3, r4			@ get offset between virt&phys
/**
 * 将proc begin和proc end转换为物理地址
 */
	add	r5, r5, r3			@ convert virt addresses to
	add	r6, r6, r3			@ physical address space
/**
 * 循环查找匹配的proc
 */
1:	ldmia	r5, {r3, r4}			@ value, mask
	and	r4, r4, r9			@ mask wanted bits
	teq	r3, r4				@ 匹配成功即退出
	beq	2f
	add	r5, r5, #PROC_INFO_SZ		@ sizeof(proc_info_list)
	cmp	r5, r6
	blo	1b
/**
 * 无法识别的CPU
 */
	mov	r5, #0				@ unknown processor
/**
 * 在初始化时，lr中保存的地址是:b __enable_mmu
 */
2:	ret	lr
ENDPROC(__lookup_processor_type)

/*
 * Look in <asm/procinfo.h> for information about the __proc_info structure.
 */
	.align	2
	.type	__lookup_processor_type_data, %object
__lookup_processor_type_data:
	.long	.
	.long	__proc_info_begin
	.long	__proc_info_end
	.size	__lookup_processor_type_data, . - __lookup_processor_type_data

__error_lpae:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_lpae
	bl 	printascii
	b	__error
str_lpae: .asciz "\nError: Kernel with LPAE support, but CPU does not support LPAE.\n"
#else
	b	__error
#endif
	.align
ENDPROC(__error_lpae)

__error_p:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_p1
	bl	printascii
	mov	r0, r9
	bl	printhex8
	adr	r0, str_p2
	bl	printascii
	b	__error
str_p1:	.asciz	"\nError: unrecognized/unsupported processor variant (0x"
str_p2:	.asciz	").\n"
	.align
#endif
ENDPROC(__error_p)

__error:
#ifdef CONFIG_ARCH_RPC
/*
 * Turn the screen red on a error - RiscPC only.
 */
	mov	r0, #0x02000000
	mov	r3, #0x11
	orr	r3, r3, r3, lsl #8
	orr	r3, r3, r3, lsl #16
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
#endif
1:	mov	r0, r0
	b	1b
ENDPROC(__error)
