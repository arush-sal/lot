// +build linux

/*
Copyright © 2019 LoT Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bpfutil

var bashreadline = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 06-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing bash commands... Hit Ctrl-C to end.\n");
	printf("%-9s %-6s %s\n", "TIME", "PID", "COMMAND");
}

uretprobe:/bin/bash:readline
{
	time("%H:%M:%S  ");
	printf("%-6d %s\n", pid, str(retval));
}`

var biolatency = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 13-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");
}

kprobe:blk_account_io_start
{
	@start[arg0] = nsecs;
}

kprobe:blk_account_io_done
/@start[arg0]/
{
	@usecs = hist((nsecs - @start[arg0]) / 1000);
	delete(@start[arg0]);
}

END
{
	clear(@start);
}`

var biosnoop = `#!/usr/bin/env bpftrace
/*
 * 15-Nov-2017	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("%-12s %-16s %-6s %7s\n", "TIME(ms)", "COMM", "PID", "LAT(ms)");
}

kprobe:blk_account_io_start
{
	@start[arg0] = nsecs;
	@iopid[arg0] = pid;
	@iocomm[arg0] = comm;
}

kprobe:blk_account_io_done
/@start[arg0] != 0 && @iopid[arg0] != 0 && @iocomm[arg0] != ""/
{
	$now = nsecs;
	printf("%-12u %-16s %-6d %7d\n",
	    elapsed / 1000000, @iocomm[arg0], @iopid[arg0],
	    ($now - @start[arg0]) / 1000000);

	delete(@start[arg0]);
	delete(@iopid[arg0]);
	delete(@iocomm[arg0]);
}

END
{
	clear(@start);
	clear(@iopid);
	clear(@iocomm);
}`

var biostacks = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 19-Mar-2019  Brendan Gregg   Created this.
 */

BEGIN
{
	printf("Tracing block I/O with init stacks. Hit Ctrl-C to end.\n");
}

kprobe:blk_account_io_start
{
	@reqstack[arg0] = kstack;
	@reqts[arg0] = nsecs;
}

kprobe:blk_start_request,
kprobe:blk_mq_start_request
/@reqts[arg0]/
{
	@usecs[@reqstack[arg0]] = hist(nsecs - @reqts[arg0]);
	delete(@reqstack[arg0]);
	delete(@reqts[arg0]);
}

END
{
	clear(@reqstack); clear(@reqts);
}`

var bitesize = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");
}

tracepoint:block:block_rq_issue
{
	@[args->comm] = hist(args->bytes);
}

END
{
	printf("\nI/O size (bytes) histograms by process name:");
}`

var capable = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing cap_capable syscalls... Hit Ctrl-C to end.\n");
	printf("%-9s %-6s %-6s %-16s %-4s %-20s AUDIT\n", "TIME", "UID", "PID",
	    "COMM", "CAP", "NAME");
	@cap[0] = "CAP_CHOWN";
	@cap[1] = "CAP_DAC_OVERRIDE";
	@cap[2] = "CAP_DAC_READ_SEARCH";
	@cap[3] = "CAP_FOWNER";
	@cap[4] = "CAP_FSETID";
	@cap[5] = "CAP_KILL";
	@cap[6] = "CAP_SETGID";
	@cap[7] = "CAP_SETUID";
	@cap[8] = "CAP_SETPCAP";
	@cap[9] = "CAP_LINUX_IMMUTABLE";
	@cap[10] = "CAP_NET_BIND_SERVICE";
	@cap[11] = "CAP_NET_BROADCAST";
	@cap[12] = "CAP_NET_ADMIN";
	@cap[13] = "CAP_NET_RAW";
	@cap[14] = "CAP_IPC_LOCK";
	@cap[15] = "CAP_IPC_OWNER";
	@cap[16] = "CAP_SYS_MODULE";
	@cap[17] = "CAP_SYS_RAWIO";
	@cap[18] = "CAP_SYS_CHROOT";
	@cap[19] = "CAP_SYS_PTRACE";
	@cap[20] = "CAP_SYS_PACCT";
	@cap[21] = "CAP_SYS_ADMIN";
	@cap[22] = "CAP_SYS_BOOT";
	@cap[23] = "CAP_SYS_NICE";
	@cap[24] = "CAP_SYS_RESOURCE";
	@cap[25] = "CAP_SYS_TIME";
	@cap[26] = "CAP_SYS_TTY_CONFIG";
	@cap[27] = "CAP_MKNOD";
	@cap[28] = "CAP_LEASE";
	@cap[29] = "CAP_AUDIT_WRITE";
	@cap[30] = "CAP_AUDIT_CONTROL";
	@cap[31] = "CAP_SETFCAP";
	@cap[32] = "CAP_MAC_OVERRIDE";
	@cap[33] = "CAP_MAC_ADMIN";
	@cap[34] = "CAP_SYSLOG";
	@cap[35] = "CAP_WAKE_ALARM";
	@cap[36] = "CAP_BLOCK_SUSPEND";
	@cap[37] = "CAP_AUDIT_READ";
}

kprobe:cap_capable
{
	$cap = arg2;
	$audit = arg3;
	time("%H:%M:%S  ");
	printf("%-6d %-6d %-16s %-4d %-20s %d\n", uid, pid, comm, $cap,
	    @cap[$cap], $audit);
}

END
{
	clear(@cap);
}`

var cpuwalk = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Sampling CPU at 99hz... Hit Ctrl-C to end.\n");
}

profile:hz:99
/pid/
{
	@cpu = lhist(cpu, 0, 1000, 1);
}`

var dcsnoop = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

#include <linux/fs.h>
#include <linux/sched.h>

// from fs/namei.c:
struct nameidata {
        struct path     path;
        struct qstr     last;
        // [...]
};

BEGIN
{
	printf("Tracing dcache lookups... Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %1s %s\n", "TIME", "PID", "COMM", "T", "FILE");
}

// comment out this block to avoid showing hits:
kprobe:lookup_fast
{
	$nd = (struct nameidata *)arg0;
	printf("%-8d %-6d %-16s R %s\n", elapsed / 1000000, pid, comm,
	    str($nd->last.name));
}

kprobe:d_lookup
{
	$name = (struct qstr *)arg1;
	@fname[tid] = $name->name;
}

kretprobe:d_lookup
/@fname[tid]/
{
	printf("%-8d %-6d %-16s M %s\n", elapsed / 1000000, pid, comm,
	    str(@fname[tid]));
	delete(@fname[tid]);
}`

var execsnoop = `#!/usr/bin/env bpftrace
/*
 * execsnoop.bt   Trace new processes via exec() syscalls.
 *                For Linux, uses bpftrace and eBPF.
 *
 * This traces when processes call exec(). It is handy for identifying new
 * processes created via the usual fork()->exec() sequence. Note that the
 * return value is not currently traced, so the exec() may have failed.
 *
 * TODO: switch to tracepoints args. Support more args. Include retval.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * 15-Nov-2017	Brendan Gregg	Created this.
 * 11-Sep-2018	   "     "	Switched to use join().
 */

BEGIN
{
	printf("%-10s %-5s %s\n", "TIME(ms)", "PID", "ARGS");
}

tracepoint:syscalls:sys_enter_execve
{
	printf("%-10u %-5d ", elapsed / 1000000, pid);
	join(args->argv);
}`

var gethostlatency = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing getaddr/gethost calls... Hit Ctrl-C to end.\n");
	printf("%-9s %-6s %-16s %6s %s\n", "TIME", "PID", "COMM", "LATms",
	    "HOST");
}

uprobe:/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo,
uprobe:/lib/x86_64-linux-gnu/libc.so.6:gethostbyname,
uprobe:/lib/x86_64-linux-gnu/libc.so.6:gethostbyname2
{
	@start[tid] = nsecs;
	@name[tid] = arg0;
}

uretprobe:/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo,
uretprobe:/lib/x86_64-linux-gnu/libc.so.6:gethostbyname,
uretprobe:/lib/x86_64-linux-gnu/libc.so.6:gethostbyname2
/@start[tid]/
{
	$latms = (nsecs - @start[tid]) / 1000000;
	time("%H:%M:%S  ");
	printf("%-6d %-16s %6d %s\n", pid, comm, $latms, str(@name[tid]));
	delete(@start[tid]);
	delete(@name[tid]);
}`

var killsnoop = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing kill() signals... Hit Ctrl-C to end.\n");
	printf("%-9s %-6s %-16s %-4s %-6s %s\n", "TIME", "PID", "COMM", "SIG",
	    "TPID", "RESULT");
}

tracepoint:syscalls:sys_enter_kill
{
	@tpid[tid] = args->pid;
	@tsig[tid] = args->sig;
}

tracepoint:syscalls:sys_exit_kill
/@tpid[tid]/
{
	time("%H:%M:%S  ");
	printf("%-6d %-16s %-4d %-6d %d\n", pid, comm, @tsig[tid], @tpid[tid],
	    args->ret);
	delete(@tpid[tid]);
	delete(@tsig[tid]);
}`

var loads = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 10-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Reading load averages... Hit Ctrl-C to end.\n");
}

interval:s:1
{
	/*
	 * See fs/proc/loadavg.c and include/linux/sched/loadavg.h for the
	 * following calculations.
	 */
	$avenrun = kaddr("avenrun");
	$load1 = *$avenrun;
	$load5 = *($avenrun + 8);
	$load15 = *($avenrun + 16);
	time("%H:%M:%S ");
	printf("load averages: %d.%03d %d.%03d %d.%03d\n",
	    ($load1 >> 11), (($load1 & ((1 << 11) - 1)) * 1000) >> 11,
	    ($load5 >> 11), (($load5 & ((1 << 11) - 1)) * 1000) >> 11,
	    ($load15 >> 11), (($load15 & ((1 << 11) - 1)) * 1000) >> 11
	);
}`

var mdflush = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

#include <linux/genhd.h>
#include <linux/bio.h>

BEGIN
{
	printf("Tracing md flush events... Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %s", "TIME", "PID", "COMM", "DEVICE");
}

kprobe:md_flush_request
{
	time("%H:%M:%S ");
	printf("%-6d %-16s %s\n", pid, comm,
	    ((struct bio *)arg1)->bi_disk->disk_name);
}`

var naptime = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 16-Feb-2019  Brendan Gregg   Created this.
 */

#include <linux/time.h>
#include <linux/sched.h>

BEGIN
{
	printf("Tracing sleeps. Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %-6s %-16s %s\n", "TIME", "PPID", "PCOMM",
	    "PID", "COMM", "SECONDS");
}

tracepoint:syscalls:sys_enter_nanosleep
/args->rqtp->tv_sec + args->rqtp->tv_nsec/
{
	$task = (struct task_struct *)curtask;
	time("%H:%M:%S ");
	printf("%-6d %-16s %-6d %-16s %d.%03d\n", $task->real_parent->pid,
	    $task->real_parent->comm, pid, comm,
	    args->rqtp->tv_sec, args->rqtp->tv_nsec / 1000000);
}`

var oomkill = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Sep-2018	Brendan Gregg	Created this.
 */

#include <linux/oom.h>

BEGIN
{
	printf("Tracing oom_kill_process()... Hit Ctrl-C to end.\n");
}

kprobe:oom_kill_process
{
	$oc = (struct oom_control *)arg1;
	time("%H:%M:%S ");
	printf("Triggered by PID %d (\"%s\"), ", pid, comm);
	printf("OOM kill of PID %d (\"%s\"), %d pages, loadavg: ",
	    $oc->chosen->pid, $oc->chosen->comm, $oc->totalpages);
	cat("/proc/loadavg");
}`

var opensnoop = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing open syscalls... Hit Ctrl-C to end.\n");
	printf("%-6s %-16s %4s %3s %s\n", "PID", "COMM", "FD", "ERR", "PATH");
}

tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat
{
	@filename[tid] = args->filename;
}

tracepoint:syscalls:sys_exit_open,
tracepoint:syscalls:sys_exit_openat
/@filename[tid]/
{
	$ret = args->ret;
	$fd = $ret > 0 ? $ret : -1;
	$errno = $ret > 0 ? 0 : - $ret;

	printf("%-6d %-16s %4d %3d %s\n", pid, comm, $fd, $errno,
	    str(@filename[tid]));
	delete(@filename[tid]);
}

END
{
	clear(@filename);
}`

var pidpersec = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 06-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing new processes... Hit Ctrl-C to end.\n");

}

tracepoint:sched:sched_process_fork
{
	@ = count();
}

interval:s:1
{
	time("%H:%M:%S PIDs/sec: ");
	print(@);
	clear(@);
}

END
{
	clear(@);
}`

var runqlat = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 17-Sep-2018	Brendan Gregg	Created this.
 */

#include <linux/sched.h>

BEGIN
{
	printf("Tracing CPU scheduler... Hit Ctrl-C to end.\n");
}

tracepoint:sched:sched_wakeup,
tracepoint:sched:sched_wakeup_new
{
	@qtime[args->pid] = nsecs;
}

tracepoint:sched:sched_switch
{
	if (args->prev_state == TASK_RUNNING) {
		@qtime[args->prev_pid] = nsecs;
	}

	$ns = @qtime[args->next_pid];
	if ($ns) {
		@usecs = hist((nsecs - $ns) / 1000);
	}
	delete(@qtime[args->next_pid]);
}

END
{
	clear(@qtime);
}`

var runqlen = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Oct-2018	Brendan Gregg	Created this.
 */

#include <linux/sched.h>

// Until BTF is available, we'll need to declare some of this struct manually,
// since it isn't avaible to be #included. This will need maintenance to match
// your kernel version. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
	struct load_weight load;
	unsigned long runnable_weight;
	unsigned int nr_running;
	unsigned int h_nr_running;
};

BEGIN
{
	printf("Sampling run queue length at 99 Hertz... Hit Ctrl-C to end.\n");
}

profile:hz:99
{
	$task = (struct task_struct *)curtask;
	$my_q = (struct cfs_rq_partial *)$task->se.cfs_rq;
	$len = $my_q->nr_running;
	$len = $len > 0 ? $len - 1 : 0;	// subtract currently runing task
	@runqlen = lhist($len, 0, 100, 1);
}`

var setuids = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 26-Feb-2019  Brendan Gregg   Created this.
 */

BEGIN
{
	printf("Tracing setuid(2) family syscalls. Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %-6s %-9s %s\n", "TIME",
	    "PID", "COMM", "UID", "SYSCALL", "ARGS (RET)");
}

tracepoint:syscalls:sys_enter_setuid,
tracepoint:syscalls:sys_enter_setfsuid
{
	@uid[tid] = uid;
	@setuid[tid] = args->uid;
	@seen[tid] = 1;
}

tracepoint:syscalls:sys_enter_setresuid
{
	@uid[tid] = uid;
	@ruid[tid] = args->ruid;
	@euid[tid] = args->euid;
	@suid[tid] = args->suid;
	@seen[tid] = 1;
}

tracepoint:syscalls:sys_exit_setuid
/@seen[tid]/
{
	time("%H:%M:%S ");
	printf("%-6d %-16s %-6d setuid    uid=%d (%d)\n", pid, comm,
	    @uid[tid], @setuid[tid], args->ret);
	delete(@seen[tid]); delete(@uid[tid]); delete(@setuid[tid]);
}

tracepoint:syscalls:sys_exit_setfsuid
/@seen[tid]/
{
	time("%H:%M:%S ");
	printf("%-6d %-16s %-6d setfsuid  uid=%d (prevuid=%d)\n", pid, comm,
	    @uid[tid], @setuid[tid], args->ret);
	delete(@seen[tid]); delete(@uid[tid]); delete(@setuid[tid]);
}

tracepoint:syscalls:sys_exit_setresuid
/@seen[tid]/
{
	time("%H:%M:%S ");
	printf("%-6d %-16s %-6d setresuid ", pid, comm, @uid[tid]);
	printf("ruid=%d euid=%d suid=%d (%d)\n", @ruid[tid], @euid[tid],
	    @suid[tid], args->ret);
	delete(@seen[tid]); delete(@uid[tid]); delete(@ruid[tid]);
	delete(@euid[tid]); delete(@suid[tid]);
}`

var statsnoop = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing stat syscalls... Hit Ctrl-C to end.\n");
	printf("%-6s %-16s %3s %s\n", "PID", "COMM", "ERR", "PATH");
}

tracepoint:syscalls:sys_enter_statfs
{
	@filename[tid] = args->pathname;
}

tracepoint:syscalls:sys_enter_statx,
tracepoint:syscalls:sys_enter_newstat,
tracepoint:syscalls:sys_enter_newlstat
{
	@filename[tid] = args->filename;
}

tracepoint:syscalls:sys_exit_statfs,
tracepoint:syscalls:sys_exit_statx,
tracepoint:syscalls:sys_exit_newstat,
tracepoint:syscalls:sys_exit_newlstat
/@filename[tid]/
{
	$ret = args->ret;
	$errno = $ret >= 0 ? 0 : - $ret;

	printf("%-6d %-16s %3d %s\n", pid, comm, $errno,
	    str(@filename[tid]));
	delete(@filename[tid]);
}

END
{
	clear(@filename);
}`

var swapin = `#!/usr/local/bin/bpftrace
/*
 * swapin - Show swapins by process.
 *
 * See BPF Performance Tools, Chapter 7, for an explanation of this tool.
 *
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 26-Jan-2019  Brendan Gregg   Created this.
 */

kprobe:swap_readpage
{
        @[comm, pid] = count();
}

interval:s:1
{
        time();
        print(@);
        clear(@);
}`

var syncsnoop = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 06-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing sync syscalls... Hit Ctrl-C to end.\n");
	printf("%-9s %-6s %-16s %s\n", "TIME", "PID", "COMM", "EVENT");
}

tracepoint:syscalls:sys_enter_sync,
tracepoint:syscalls:sys_enter_syncfs,
tracepoint:syscalls:sys_enter_fsync,
tracepoint:syscalls:sys_enter_fdatasync,
tracepoint:syscalls:sys_enter_sync_file_range,
tracepoint:syscalls:sys_enter_msync
{
	time("%H:%M:%S  ");
	printf("%-6d %-16s %s\n", pid, comm, probe);
}`

var syscount = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 13-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Counting syscalls... Hit Ctrl-C to end.\n");
	// ausyscall --dump | awk 'NR > 1 { printf("\t@sysname[%d] = \"%s\";\n", $1, $2); }'
}

tracepoint:raw_syscalls:sys_enter
{
	@syscall[args->id] = count();
	@process[comm] = count();
}

END
{
	printf("\nTop 10 syscalls IDs:\n");
	print(@syscall, 10);
	clear(@syscall);

	printf("\nTop 10 processes:\n");
	print(@process, 10);
	clear(@process);
}`

var tcpaccept = `#!/usr/bin/env bpftrace
/*
 * Copyright (c) 2018 Dale Hamel.
 * Licensed under the Apache License, Version 2.0 (the "License")

 * 23-Nov-2018	Dale Hamel	created this.
 */

#include <linux/socket.h>
#include <net/sock.h>

BEGIN
{
	printf("Tracing TCP accepts. Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-14s ", "TIME", "PID", "COMM");
	printf("%-39s %-5s %-39s %-5s %s\n", "RADDR", "RPORT", "LADDR",
	    "LPORT", "BL");
}

kretprobe:inet_csk_accept
{
	$sk = (struct sock *)retval;
	$inet_family = $sk->__sk_common.skc_family;

	if ($inet_family == AF_INET || $inet_family == AF_INET6) {
		// initialize variable type:
		$daddr = ntop(0);
		$saddr = ntop(0);
		if ($inet_family == AF_INET) {
			$daddr = ntop($sk->__sk_common.skc_daddr);
			$saddr = ntop($sk->__sk_common.skc_rcv_saddr);
		} else {
			$daddr = ntop(
			    $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
			$saddr = ntop(
			    $sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		}
		$lport = $sk->__sk_common.skc_num;
		$dport = $sk->__sk_common.skc_dport;
		$qlen  = $sk->sk_ack_backlog;
		$qmax  = $sk->sk_max_ack_backlog;

		// Destination port is big endian, it must be flipped
		$dport = ($dport >> 8) | (($dport << 8) & 0x00FF00);

		time("%H:%M:%S ");
		printf("%-6d %-14s ", pid, comm);
		printf("%-39s %-5d %-39s %-5d ", $daddr, $dport, $saddr,
		    $lport);
		printf("%d/%d\n", $qlen, $qmax);
	}
}`

var tcpconnect = `#!/usr/bin/env bpftrace
/*
 * Copyright (c) 2018 Dale Hamel.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 23-Nov-2018	Dale Hamel	created this.
 */

#include <linux/socket.h>
#include <net/sock.h>

BEGIN
{
  printf("Tracing tcp connections. Hit Ctrl-C to end.\n");
  printf("%-8s %-8s %-16s ", "TIME", "PID", "COMM");
  printf("%-39s %-6s %-39s %-6s\n", "SADDR", "SPORT", "DADDR", "DPORT");
}

kprobe:tcp_connect
{
  $sk = ((struct sock *) arg0);
  $inet_family = $sk->__sk_common.skc_family;

  if ($inet_family == AF_INET || $inet_family == AF_INET6) {
    if ($inet_family == AF_INET) {
      $daddr = ntop($sk->__sk_common.skc_daddr);
      $saddr = ntop($sk->__sk_common.skc_rcv_saddr);
    } else {
      $daddr = ntop($sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
      $saddr = ntop($sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    }
    $lport = $sk->__sk_common.skc_num;
    $dport = $sk->__sk_common.skc_dport;

    // Destination port is big endian, it must be flipped
    $dport = ($dport >> 8) | (($dport << 8) & 0x00FF00);

    time("%H:%M:%S ");
    printf("%-8d %-16s ", pid, comm);
    printf("%-39s %-6d %-39s %-6d\n", $saddr, $lport, $daddr, $dport);
  }
}`

var tcpdrop = `#!/usr/bin/env bpftrace
/*
 * Copyright (c) 2018 Dale Hamel.
 * Licensed under the Apache License, Version 2.0 (the "License")

 * 23-Nov-2018	Dale Hamel	created this.
 */

#include <linux/socket.h>
#include <net/sock.h>

BEGIN
{
  printf("Tracing tcp drops. Hit Ctrl-C to end.\n");
  printf("%-8s %-8s %-16s %-21s %-21s %-8s\n", "TIME", "PID", "COMM", "SADDR:SPORT", "DADDR:DPORT", "STATE");

  // See https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
  @tcp_states[1] = "ESTABLISHED";
  @tcp_states[2] = "SYN_SENT";
  @tcp_states[3] = "SYN_RECV";
  @tcp_states[4] = "FIN_WAIT1";
  @tcp_states[5] = "FIN_WAIT2";
  @tcp_states[6] = "TIME_WAIT";
  @tcp_states[7] = "CLOSE";
  @tcp_states[8] = "CLOSE_WAIT";
  @tcp_states[9] = "LAST_ACK";
  @tcp_states[10] = "LISTEN";
  @tcp_states[11] = "CLOSING";
  @tcp_states[12] = "NEW_SYN_RECV";
}

kprobe:tcp_drop
{
  $sk = ((struct sock *) arg0);
  $inet_family = $sk->__sk_common.skc_family;

  if ($inet_family == AF_INET || $inet_family == AF_INET6) {
    if ($inet_family == AF_INET) {
      $daddr = ntop($sk->__sk_common.skc_daddr);
      $saddr = ntop($sk->__sk_common.skc_rcv_saddr);
    } else {
      $daddr = ntop($sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
      $saddr = ntop($sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    }
    $lport = $sk->__sk_common.skc_num;
    $dport = $sk->__sk_common.skc_dport;

    // Destination port is big endian, it must be flipped
    $dport = ($dport >> 8) | (($dport << 8) & 0x00FF00);

    $state = $sk->__sk_common.skc_state;
    $statestr = @tcp_states[$state];

    time("%H:%M:%S ");
    printf("%-8d %-16s ", pid, comm);
    printf("%39s:%-6d %39s:%-6d %-10s\n", $saddr, $lport, $daddr, $dport, $statestr);
    printf("%s\n", kstack);
  }
}

END
{
  clear(@tcp_states);
}`

var tcplife = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 17-Apr-2019  Brendan Gregg   Created this.
 */

#include <net/tcp_states.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/tcp.h>

BEGIN
{
	printf("%-5s %-10s %-15s %-5s %-15s %-5s ", "PID", "COMM",
	    "LADDR", "LPORT", "RADDR", "RPORT");
	printf("%5s %5s %s\n", "TX_KB", "RX_KB", "MS");
}

kprobe:tcp_set_state
{
	$sk = (struct sock *)arg0;
	$newstate = arg1;

	/*
	 * This tool includes PID and comm context. From TCP this is best
	 * effort, and may be wrong in some situations. It does this:
	 * - record timestamp on any state < TCP_FIN_WAIT1
	 *	note some state transitions may not be present via this kprobe
	 * - cache task context on:
	 *	TCP_SYN_SENT: tracing from client
	 *	TCP_LAST_ACK: client-closed from server
	 * - do output on TCP_CLOSE:
	 *	fetch task context if cached, or use current task
	 */

	// record first timestamp seen for this socket
	if ($newstate < TCP_FIN_WAIT1 && @birth[$sk] == 0) {
		@birth[$sk] = nsecs;
	}

	// record PID & comm on SYN_SENT
	if ($newstate == TCP_SYN_SENT || $newstate == TCP_LAST_ACK) {
		@skpid[$sk] = pid;
		@skcomm[$sk] = comm;
	}

	// session ended: calculate lifespan and print
	if ($newstate == TCP_CLOSE && @birth[$sk]) {
		$delta_ms = (nsecs - @birth[$sk]) / 1000000;
		$lport = $sk->__sk_common.skc_num;
		$dport = $sk->__sk_common.skc_dport;
		$dport = ($dport >> 8) | (($dport << 8) & 0xff00);
		$tp = (struct tcp_sock *)$sk;
		$pid = @skpid[$sk];
		$comm = @skcomm[$sk];
		if ($comm == "") {
			// not cached, use current task
			$pid = pid;
			$comm = comm;
		}

		$family = $sk->__sk_common.skc_family;
		$saddr = ntop(0);
		$daddr = ntop(0);
		if ($family == AF_INET) {
			$saddr = ntop(AF_INET, $sk->__sk_common.skc_rcv_saddr);
			$daddr = ntop(AF_INET, $sk->__sk_common.skc_daddr);
		} else {
			// AF_INET6
			$saddr = ntop(AF_INET6,
			    $sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
			$daddr = ntop(AF_INET6,
			    $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
		}
		printf("%-5d %-10.10s %-15s %-5d %-15s %-6d ", $pid,
		    $comm, $saddr, $lport, $daddr, $dport);
		printf("%5d %5d %d\n", $tp->bytes_acked / 1024,
		    $tp->bytes_received / 1024, $delta_ms);

		delete(@birth[$sk]);
		delete(@skpid[$sk]);
		delete(@skcomm[$sk]);
	}
}

END
{
	clear(@birth); clear(@skpid); clear(@skcomm);
}`

var tcpretrans = `#!/usr/bin/env bpftrace
/*
 * Copyright (c) 2018 Dale Hamel.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 23-Nov-2018  Dale Hamel      created this.
 */

#include <linux/socket.h>
#include <net/sock.h>

BEGIN
{
	printf("Tracing tcp retransmits. Hit Ctrl-C to end.\n");
	printf("%-8s %-8s %20s %21s %6s\n", "TIME", "PID", "LADDR:LPORT",
	    "RADDR:RPORT", "STATE");

	// See include/net/tcp_states.h:
	@tcp_states[1] = "ESTABLISHED";
	@tcp_states[2] = "SYN_SENT";
	@tcp_states[3] = "SYN_RECV";
	@tcp_states[4] = "FIN_WAIT1";
	@tcp_states[5] = "FIN_WAIT2";
	@tcp_states[6] = "TIME_WAIT";
	@tcp_states[7] = "CLOSE";
	@tcp_states[8] = "CLOSE_WAIT";
	@tcp_states[9] = "LAST_ACK";
	@tcp_states[10] = "LISTEN";
	@tcp_states[11] = "CLOSING";
	@tcp_states[12] = "NEW_SYN_RECV";
}

kprobe:tcp_retransmit_skb
{
	$sk = (struct sock *)arg0;
	$inet_family = $sk->__sk_common.skc_family;

	if ($inet_family == AF_INET || $inet_family == AF_INET6) {
		// initialize variable type:
		$daddr = ntop(0);
		$saddr = ntop(0);
		if ($inet_family == AF_INET) {
			$daddr = ntop($sk->__sk_common.skc_daddr);
			$saddr = ntop($sk->__sk_common.skc_rcv_saddr);
		} else {
			$daddr = ntop(
			    $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
			$saddr = ntop(
			    $sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		}
		$lport = $sk->__sk_common.skc_num;
		$dport = $sk->__sk_common.skc_dport;

		// Destination port is big endian, it must be flipped
		$dport = ($dport >> 8) | (($dport << 8) & 0x00FF00);

		$state = $sk->__sk_common.skc_state;
		$statestr = @tcp_states[$state];

		time("%H:%M:%S ");
		printf("%-8d %14s:%-6d %14s:%-6d %6s\n", pid, $saddr, $lport,
		    $daddr, $dport, $statestr);
	}
}

END
{
	clear(@tcp_states);
}`

var tcpsynbl = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 19-Apr-2019  Brendan Gregg   Created this.
 */

#include <net/sock.h>

BEGIN
{
	printf("Tracing SYN backlog size. Ctrl-C to end.\n");
}

kprobe:tcp_v4_syn_recv_sock,
kprobe:tcp_v6_syn_recv_sock
{
	$sock = (struct sock *)arg0;
	@backlog[$sock->sk_max_ack_backlog & 0xffffffff] =
	    hist($sock->sk_ack_backlog);
	if ($sock->sk_ack_backlog > $sock->sk_max_ack_backlog) {
		time("%H:%M:%S dropping a SYN.\n");
	}
}

END
{
	printf("\n@backlog[backlog limit]: histogram of backlog size\n");
}`

var threadsnoop = `#!/usr/local/bin/bpftrace
/*
 * Copyright (c) 2019 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 15-Feb-2019  Brendan Gregg   Created this.
 */

BEGIN
{
	printf("%-10s %-6s %-16s %s\n", "TIME(ms)", "PID", "COMM", "FUNC");
}

uprobe:/lib/x86_64-linux-gnu/libpthread.so.0:pthread_create
{
	printf("%-10u %-6d %-16s %s\n", elapsed / 1000000, pid, comm,
	    usym(arg2));
}`

var vfscount = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 06-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing VFS calls... Hit Ctrl-C to end.\n");

}

kprobe:vfs_*
{
	@[func] = count();
}`

var vfsstat = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 06-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing key VFS calls... Hit Ctrl-C to end.\n");

}

kprobe:vfs_read*,
kprobe:vfs_write*,
kprobe:vfs_fsync,
kprobe:vfs_open,
kprobe:vfs_create
{
	@[func] = count();
}

interval:s:1
{
	time();
	print(@);
	clear(@);
}

END
{
	clear(@);
}`

var writeback = `#!/usr/bin/env bpftrace
/*
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 14-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing writeback... Hit Ctrl-C to end.\n");
	printf("%-9s %-8s %-8s %-16s %s\n", "TIME", "DEVICE", "PAGES",
	    "REASON", "ms");

	// see /sys/kernel/debug/tracing/events/writeback/writeback_start/format
	@reason[0] = "background";
	@reason[1] = "vmscan";
	@reason[2] = "sync";
	@reason[3] = "periodic";
	@reason[4] = "laptop_timer";
	@reason[5] = "free_more_memory";
	@reason[6] = "fs_free_space";
	@reason[7] = "forker_thread";
}

tracepoint:writeback:writeback_start
{
	@start[args->sb_dev] = nsecs;
}

tracepoint:writeback:writeback_written
{
	$sb_dev = args->sb_dev;
	$s = @start[$sb_dev];
	delete(@start[$sb_dev]);
	$lat = $s ? (nsecs - $s) / 1000 : 0;

	time("%H:%M:%S  ");
	printf("%-8s %-8d %-16s %d.%03d\n", args->name,
	    args->nr_pages & 0xffff,	// TODO: explain these bitmasks
	    @reason[args->reason & 0xffffffff],
	    $lat / 1000, $lat % 1000);
}

END
{
	clear(@reason);
	clear(@start);
}`

var xfsdist = `#!/usr/bin/env bpftrace
/*
 * xfsdist	Summarize XFS operation latency.
 *		For Linux, uses bpftrace and eBPF.
 *
 * This traces four common file system calls: read, write, open, and fsync.
 * It can be customized to trace more if desired.
 *
 * USAGE: xfsdist.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 08-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Tracing XFS operation latency... Hit Ctrl-C to end.\n");
}

kprobe:xfs_file_read_iter,
kprobe:xfs_file_write_iter,
kprobe:xfs_file_open,
kprobe:xfs_file_fsync
{
	@start[tid] = nsecs;
	@name[tid] = func;
}

kretprobe:xfs_file_read_iter,
kretprobe:xfs_file_write_iter,
kretprobe:xfs_file_open,
kretprobe:xfs_file_fsync
/@start[tid]/
{
	@us[@name[tid]] = hist((nsecs - @start[tid]) / 1000);
	delete(@start[tid]);
	delete(@name[tid]);
}

END
{
	clear(@start);
	clear(@name);
}`
