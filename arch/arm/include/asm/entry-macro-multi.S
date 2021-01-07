#include <asm/assembler.h>

/*
 * Interrupt handling.  Preserves r7, r8, r9
 */
	.macro	arch_irq_handler_default
	get_irqnr_preamble r6, lr
/**
 * 获得中断编号
 */
1:	get_irqnr_and_base r0, r2, r6, lr
/**
 * 当前sp正好指向pt_regs
 */
	movne	r1, sp
	@
	@ routine called with r0 = irq number, r1 = struct pt_regs *
	@
/**
 * 错误的中断就退出
 */
	badrne	lr, 1b
/**
 * 中断号正确，处理中断
 */
	bne	asm_do_IRQ

#ifdef CONFIG_SMP
	/*
	 * XXX
	 *
	 * this macro assumes that irqstat (r2) and base (r6) are
	 * preserved from get_irqnr_and_base above
	 */
	ALT_SMP(test_for_ipi r0, r2, r6, lr)
	ALT_UP_B(9997f)
	movne	r1, sp
	badrne	lr, 1b
	bne	do_IPI
#endif
9997:
	.endm

	.macro	arch_irq_handler, symbol_name
	.align	5
	.global \symbol_name
\symbol_name:
	mov	r8, lr
	arch_irq_handler_default
	ret	r8
	.endm
