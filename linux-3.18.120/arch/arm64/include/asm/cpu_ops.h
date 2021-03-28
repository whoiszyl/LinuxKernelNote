/*
 * Copyright (C) 2013 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_CPU_OPS_H
#define __ASM_CPU_OPS_H

#include <linux/init.h>
#include <linux/threads.h>

struct device_node;

/**
 * struct cpu_operations - Callback operations for hotplugging CPUs.
 *
 * @name:	Name of the property as appears in a devicetree cpu node's
 *		enable-method property.
 * @cpu_init:	Reads any data necessary for a specific enable-method from the
 *		devicetree, for a given cpu node and proposed logical id.
 * @cpu_init_idle: Reads any data necessary to initialize CPU idle states from
 *		devicetree, for a given cpu node and proposed logical id.
 * @cpu_prepare: Early one-time preparation step for a cpu. If there is a
 *		mechanism for doing so, tests whether it is possible to boot
 *		the given CPU.
 * @cpu_boot:	Boots a cpu into the kernel.
 * @cpu_postboot: Optionally, perform any post-boot cleanup or necesary
 *		synchronisation. Called from the cpu being booted.
 * @cpu_disable: Prepares a cpu to die. May fail for some mechanism-specific
 * 		reason, which will cause the hot unplug to be aborted. Called
 * 		from the cpu to be killed.
 * @cpu_die:	Makes a cpu leave the kernel. Must not fail. Called from the
 *		cpu being killed.
 * @cpu_kill:  Ensures a cpu has left the kernel. Called from another cpu.
 * @cpu_suspend: Suspends a cpu and saves the required context. May fail owing
 *               to wrong parameters or error conditions. Called from the
 *               CPU being suspended. Must be called with IRQs disabled.
 */
 /* 该接口提供了一些CPU操作相关的回调函数，由底层代码（可以称作cpu ops driver）
  *	根据实际情况实现，并由ARM64的SMP模块调用
  */
struct cpu_operations {
	const char	*name;//operations的名字，需要唯一
	int		(*cpu_init)(struct device_node *, unsigned int);//cpu operations的初始化接口，会在SMP初始化时调用，
															//cpu ops driver可以在这个接口中，完成一些必须的初始化动作，
															//如读取寄存器值、从DTS中获取配置等
	int		(*cpu_init_idle)(struct device_node *, unsigned int);//CPU idle有关的初始化接口，会由cpuidle driver在初始化时调用。
																 //cpu ops driver可以在这个接口中实现和idle有关的初始化操作
	int		(*cpu_prepare)(unsigned int);//CPU boot有关的接口，在boot前调用
	int		(*cpu_boot)(unsigned int);//CPU boot有关的接口，在boot时调用
	void		(*cpu_postboot)(void);//CPU boot有关的接口，在boot后调用
//如果使能了hotplug功能，除了boot接口之外，需要额外实现用于关闭CPU（和 boot相对）的接口
#ifdef CONFIG_HOTPLUG_CPU
	int		(*cpu_disable)(unsigned int cpu);
	void		(*cpu_die)(unsigned int cpu);
	int		(*cpu_kill)(unsigned int cpu);
#endif
#ifdef CONFIG_ARM64_CPU_SUSPEND
	int		(*cpu_suspend)(unsigned long);//如果使能了CPU suspend功能，则由cpu_suspend完成相应的suspend动作
#endif
};

extern const struct cpu_operations *cpu_ops[NR_CPUS];
int __init cpu_read_ops(struct device_node *dn, int cpu);
void __init cpu_read_bootcpu_ops(void);

#endif /* ifndef __ASM_CPU_OPS_H */
