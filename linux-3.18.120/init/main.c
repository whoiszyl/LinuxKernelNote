/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/tty.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_cgroup.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/kmemcheck.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>
#endif

static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(unsigned long);
extern void radix_tree_init(void);
#ifndef CONFIG_DEBUG_RODATA
static inline void mark_rodata_ro(void) { }
#endif

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Command line for per-initcall parameter parsing */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situaiton where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static int __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	int had_early_param = 0;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
static int __init repair_env_string(char *param, char *val, const char *unused)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val, const char *unused)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val, unused);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val, const char *unused)
{
	repair_env_string(param, val, unused);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
#ifdef CONFIG_X86_LOCAL_APIC
static void __init smp_init(void)
{
	APIC_init_uniprocessor();
}
#else
#define smp_init()	do { } while (0)
#endif

static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy(saved_command_line, boot_command_line);
	strcpy(static_command_line, command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

static noinline void __init_refok rest_init(void)
{
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	kernel_thread(kernel_init, NULL, CLONE_FS);
	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();
	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	init_idle_bootup_task(current);
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val, const char *unused)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

/*
 *	Activate the first processor.
 */

static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_info_cache_init(void)
{
}
#endif

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_cgroup_init_flatmem();
	mem_init();
	kmem_cache_init();
	percpu_init_late();
	pgtable_init();
	vmalloc_init();
}

asmlinkage __visible void __init start_kernel(void)
{
    /* 
    asmlinkage  
    宏的作用：1、让传送给函数的参数全部使用栈式传送，而不用寄存器传送； 
             2、声明这个函数是给汇编代码调用的；(但是在ARM架构下(/include/linux/linkage.h)，这个宏没有定义，所以没用) 
    __init 
    宏的作用：1、告诉编译器将此代码放在制定代码段(.init.text)中  
    (/include/linux/init.h) #define __init      __section(.init.text) __cold notrace 
    */  

	char *command_line;
	char *after_dashes;

	/*
	 * Need to run as early as possible, to initialize the
	 * lockdep hash:
	 */
	lockdep_init(); //在ARM11中此函数为空，作用是初始化哈希表  
	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();//当CPU是多处理器时获取多处理器的ID，当CPU是单核是时此函数为空  
	debug_objects_early_init();//在调试的时候用  

	/*
	 * Set up the the initial canary ASAP:
	 */
	boot_init_stack_canary(); //在ARM11中此函数为空，作用是初始化哈希表  

	cgroup_init_early(); //控制组的早期初始化，控制组是什么？参考：/Documentation/cgroups/cgroups.txt  

	local_irq_disable(); //关闭系统总中断  
	early_boot_irqs_disabled = true;

/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */
	boot_cpu_init();//激活当前CPU（在内核全局变量中将当前CPU的状态设为激活状态） 
	page_address_init();//初始化高端内存 
	pr_notice("%s", linux_banner); //打印出Linux内核版本等信息  
	setup_arch(&command_line);//CPU架构相关的初始化，处理uboot传递的tag参数和命令行参数，初始化内存页表  
	mm_init_cpumask(&init_mm);//内容涉及到内存管理子系统
	setup_command_line(command_line);//保存命令行参数  
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
							//这三个函数与多核处理器有关
	build_all_zonelists(NULL, NULL);//建立系统内存页区链表 
	page_alloc_init();//当配置了 CONFIG_HOTPLUG_CPU (CPU热拔插)此函数才有用，  
    				  //CPU热拔插 ，这种高级特性主要针对服务器的多CPU环境和虚拟机中  

	pr_notice("Kernel command line: %s\n", boot_command_line);//打印command line参数 

    //解析命令行参数
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   set_init_arg);

	jump_label_init();

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	pidhash_init();//初始化进程PID的哈希表，便于通过PID访问进程结构信息
	vfs_caches_init_early();    //虚拟文件系统的缓存初始化，目录项缓存(Dentry cache) 节点缓存(Inode-cache)  
    							//主要是初始化几个哈希表  
	sort_main_extable();//对内核内部的异常表进行排序
	trap_init();//对硬件中断向量进行初始化，在ARM系统里是空函数，没有任何的初始化 
	mm_init();//设置内核内存分配器，对内存的使用情况进行标记，以及指定哪些内存可以被分配 

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();//初始化任务调度器  
   				 //在任何中断前初始化任务调度器  
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();//关闭优先级调度，优先级高的任务可以抢占优先级低的任务  

	//判断中断是否关闭，若没有则内核会发出警告，并关闭中断
	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();


	idr_init_cache();//创建IDR机制的内存缓存对象
	rcu_init();//RCU(Read-Copy Update)，顾名思义就是读-拷贝修改，它是基于其原理命名的。对于被RCU保护的共享数据结构，  
   			   //读者不需要获得任何锁就可以访问它，但写者在访问它时首先拷贝一个副本，然后对副本进行修改，  
  			   //最后使用一个回调（callback）机制在适当的时机把指向原来数据的指针重新指向新的被修改的数据。  
  			   //这个时机就是所有引用该数据的CPU都退出对共享数据的操作。  
	context_tracking_init();
	radix_tree_init();//内核radix树算法初始化 Linux基数树(radix tree)
	/* init some links before init_ISA_irqs() */
	early_irq_init();//前期外部中断描述符初始化，主要初始化数据结构
	init_IRQ();//对应构架特定的中断初始化函数  machine_desc->init_irq();  
   	 		   //也就是运行设备描述结构体中的init_irq函数，此函数一般在板级初始化文件（arch/*/mach-*/board-*.c）中定义  
	tick_init();//作用是初始化时钟事件管理器的回调函数  
	rcu_init_nohz();
	init_timers();//主要初始化引导CPU的时钟相关的数据结构，注册时钟的回调函数，  
    			  //当时钟到达时可以回调时钟处理函数，最后初始化时钟软件中断处理。
	hrtimers_init();//初始化高精度的定时器，并设置回调函数 
	softirq_init();//初始化软件中断，软件中断与硬件中断区别就是中断发生时，  
   				   //软件中断是使用线程来监视中断信号，而硬件中断是使用CPU硬件来监视中断  
	timekeeping_init();//函数是初始化系统时钟计时，并且初始化内核里与时钟计时相关的变量  
	time_init();//构架相关的，旨在开启一个硬件定时器，开始产生系统时钟
	sched_clock_postinit();
	perf_event_init();//CPU性能监视机制初始化 依赖于 CONFIG_PERF_EVENTS 这个宏，在ARM里面没有配置，所以次函数为空  
    			      //此机制包括CPU同一时间执行指令数，cache miss数，分支预测失败次数等性能参数 
	profile_init();//函数是分配内核性能统计保存的内存，以便统计的性能变量可以保存到这里  
    			   //内核的性能调试工具
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n"); //提示中断是否过早地打开 
	early_boot_irqs_disabled = false; //设置启动早期IRQ使能标志，允许IRQ使能 
	local_irq_enable();//开中断 

	kmem_cache_init_late();//初始化 slab 内存分配器 

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();//控制台初始化,现在才可以输出内容到终端，在这之前的输出内容都是保存在缓冲区内的

	//判断输入的参数是否出错，若出错就打印处错误
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);


	lockdep_info();//打印锁的依赖信息，用调试锁，在ARM中此函数为空

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();//测试锁的 API 是否使用正常  
    				   //依赖于 CONFIG_DEBUG_LOCKING_API_SELFTESTS 宏，在ARM中没有定义此宏



// CONFIG_BLK_DEV_INITRD 此宏是配置内核支持 RAM filesystem 和 RAM disk   
// page_to_pfn() 将mem_map_t类型的页管理单元page,转换为它所管理的页对应的物理页帧号  
// pfn_to_page() 将物理页帧号转换为管理该页的mem_map_t类型指针page  
#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	page_cgroup_init();    //给 (cgroup) 控制组分配内存  
    					   //依赖 CONFIG_CGROUP_MEM_RES_CTLR sysctl_init()和do_initcalls()和 CONFIG_SPARSEMEM 宏，在ARM中此函数为空  
	debug_objects_mem_init();//建立高速缓冲池跟踪内存操作  
   							 //依赖 CONFIG_DEBUG_OBJECTS 宏，调试的时候使用，在ARM中此函数为空 
	kmemleak_init();//初始化内存泄漏控制器，将泄漏的内存集合重新配置为可用内存  
                    //依赖 CONFIG_DEBUG_KMEMLEAK 在ARM中次函数为空
	setup_per_cpu_pageset();//这个函数是创建每个CPU的高速缓存集合数组。因为每个CPU都不定时需要使用一些页面内存和释放页面内存，  
                            //为了提高效率，就预先创建一些内存页面作为每个CPU的页面集合。 
	numa_policy_init(); // numa 策略初始化   
					    //NUMA，它是NonUniform Memory AccessAchitecture的缩写，主要用来提高多个CPU访问内存的速度。  
					    //因为多个CPU访问同一个节点的内存速度远远比访问多个节点的速度来得快  
					    //依赖 CONFIG_NUMA 宏，在ARM中此函数为空 

	//时钟相关的后期初始化，没找到函数体，是一个函数指针，函数体应该在架构相关的代码里面  
	if (late_time_init)
		late_time_init();
	sched_clock_init();//初始化调度时钟  
	calibrate_delay();  //校准时间延迟参数值  
					    //校准原理是计算出cpu在一秒钟内执行了多少次一个极短的循环，     
					    //计算出来的值经过处理后得到BogoMIPS 值，     
					    //Bogo是Bogus(伪)的意思，MIPS是millions of instructions per second  
					    //(百万条指令每秒)的缩写
	pidmap_init();//函数是进程位图初始化，一般情况下使用一页来表示所有进程占用情况
	anon_vma_init();//反向映射匿名虚拟内存域（ anonymous VMA）（没有映射文件的虚拟内存）初始化  
  				    //提供反向查找内存的结构指针位置  
  				    //是PFRA（页框回收算法）技术中的组成部分  
	acpi_early_init();

//x86 CPU专用的 
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
#ifdef CONFIG_X86_ESPFIX64
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
#endif
	thread_info_cache_init();//线程信息缓存初始化，在ARM中此函数为空
	cred_init();//分配一块内存用于存放credentials(证书)(详见：Documentation/credentials.txt) 
	fork_init(totalram_pages);//进程创建机制初始化，为内核"task_struct"分配空间  
    						  //据当前物理内存计算出来可以创建进程（线程）的数量
	proc_caches_init();//给进程的各种资源管理结构分配了相应的对象缓存区
	buffer_init();//缓存系统初始化，创建缓存头空间  
			      //Limit the bh occupancy to 10% of ZONE_NORMAL  
			      //限制 buffer_head 占用 ZONE_NORMAL(896Mb) 的 10%  
			      //物理内存被划分为三个区来管理，它们是ZONE_DMA、ZONE_NORMAL 和ZONE_HIGHMEM 
	key_init();//初始化密钥管理器  
               //依赖 CONFIG_KEYS 宏 
	security_init();//内核安全框架初始化  
                    //依赖 CONFIG_SECURITY_NETWORK 宏 
	dbg_late_init();//内核调试系统初始化  
                    //依赖 CONFIG_KGDB 宏 
	vfs_caches_init(totalram_pages);//虚拟文件系统进行缓存初始化，提高虚拟文件系统的访问速度 
	signals_init();//初始化信号队列
	/* rootfs populating might need page-writeback */
	page_writeback_init();//页回写机制初始化  
   						  //页回写机制 => 将页高速缓存中的变更数据刷新回磁盘的操作
	proc_root_init();//proc文件系统初始化 挂载在/proc 目录下  
				     //proc是一种伪文件系统（也即虚拟文件系统），存储的是当前内核运行状态的一系列特殊文件，  
				     //用户可以通过这些文件查看有关系统硬件及当前正在运行进程的信息，  
				     //甚至可以通过更改其中某些文件来改变内核的运行状态 
	cgroup_init();//控制组初始化，前面有个 cgroup_init_early();  
	cpuset_init();    /* 
					      CPUSET功能 
					      在Linux中要控制每一個程序在那個核心執行，可以使用CPUSET的功能。 
					      CPUSET是Linux核心2.6版中的一個小模組，它可以讓使用者將多核心的系統切割成不同區域， 
					      每個區域包括了處理器和实际内存位置。使用者可以指定某個程式只能在特定的區域執行， 
					      而且該程式不能使用該區域之外的計算資源 
   					 */  
   					 //依赖 CONFIG_CPUSETS 宏 
	taskstats_init_early();    //初始化任务状态相关的缓存、队列和信号量。任务状态主要向用户提供任务的状态信息。  
    						   //初始化读写互斥机制  
   							   //依赖 CONFIG_TASKSTATS 宏 
	delayacct_init();//初始化每个任务延时计数。当一个任务等CPU运行，或者等IO同步时，都需要计算等待时间  
   					 //依赖 CONFIG_TASK_DELAY_ACCT 宏

	check_bugs();//检查CPU配置、FPU等是否非法使用不具备的功能  
   				 //在ARM架构下check_writebuffer_bugs 测试写缓存一致性 

	acpi_subsystem_init();//ACPI - Advanced Configuration and Power Interface高级配置及电源接口  
                          //电源管理方面的初始化  
                          //依赖 CONFIG_ACPI 宏 
	sfi_init_late();//SFI - Simple Firmware Interface  
    				//一个轻量级的方法用于平台固件通过固定的内存页表传递信息给操作系统  
    				//依赖 CONFIG_SFI 宏 

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_late_init();
		efi_free_boot_services();
	}

	ftrace_init();//初始化内核跟踪模块，ftrace的作用是帮助开发人员了解Linux 内核的运行时行为，  
   				  //以便进行故障调试或性能分析 

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();//后继初始化，主要是创建内核线程init，并运行 
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = alloc_bootmem(sizeof(*entry));
			entry->buf = alloc_bootmem(strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct list_head *tmp;
	struct blacklist_entry *entry;
	char *fn_name;

	fn_name = kasprintf(GFP_KERNEL, "%pf", fn);
	if (!fn_name)
		return false;

	list_for_each(tmp, &blacklisted_initcalls) {
		entry = list_entry(tmp, struct blacklist_entry, next);
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			kfree(fn_name);
			return true;
		}
	}

	kfree(fn_name);
	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
	ktime_t calltime, delta, rettime;
	unsigned long long duration;
	int ret;

	printk(KERN_DEBUG "calling  %pF @ %i\n", fn, task_pid_nr(current));
	calltime = ktime_get();
	ret = fn();
	rettime = ktime_get();
	delta = ktime_sub(rettime, calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	printk(KERN_DEBUG "initcall %pF returned %d after %lld usecs\n",
		 fn, ret, duration);

	return ret;
}

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	int ret;
	char msgbuf[64];

	if (initcall_blacklisted(fn))
		return -EPERM;

	if (initcall_debug)
		ret = do_one_initcall_debug(fn);
	else
		ret = fn();

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

	return ret;
}


extern initcall_t __initcall_start[];
extern initcall_t __initcall0_start[];
extern initcall_t __initcall1_start[];
extern initcall_t __initcall2_start[];
extern initcall_t __initcall3_start[];
extern initcall_t __initcall4_start[];
extern initcall_t __initcall5_start[];
extern initcall_t __initcall6_start[];
extern initcall_t __initcall7_start[];
extern initcall_t __initcall_end[];

static initcall_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static char *initcall_level_names[] __initdata = {
	"early",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static void __init do_initcall_level(int level)
{
	initcall_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   &repair_env_string);

	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
	int level;

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	usermodehelper_init();
	shmem_init();
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	do_initcalls();//初始化内核子系统和内建的设备驱动
	random_int_secret_init();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_t *fn;

	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(*fn);
}

/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 */
void __init load_default_modules(void)
{
	load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	return do_execve(getname_kernel(init_filename),
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

static int __ref kernel_init(void *unused)
{
	int ret;

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	free_initmem();
	mark_rodata_ro();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	flush_delayed_fput();

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",
			execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/init.txt for guidance.");
}

static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);
	/*
	 * init can run on any cpu.
	 */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	cad_pid = task_pid(current);

	smp_prepare_cpus(setup_max_cpus);

	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 */

	/* rootfs is available now, try loading default modules */
	load_default_modules();
}
