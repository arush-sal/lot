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

var bashreadlineDesc = "Print entered bash commands from all running shells."
var biolatencyDesc = "Block I/O latency as a histogram."
var biosnoopDesc = "Block I/O tracing tool, showing per I/O latency."
var biostacksDesc = "Show disk I/O latency with initialization stacks."
var bitesizeDesc = "Show disk I/O size as a histogram."
var capableDesc = "Trace security capabilitiy checks (cap_capable())."
var cpuwalkDesc = "Sample which CPUs are executing processes."
var dcsnoopDesc = "Trace directory entry cache (dcache) lookups."
var execsnoopDesc = "Trace new processes via exec() syscalls."
var gethostlatencyDesc = "Trace getaddrinfo/gethostbyname[2] calls."
var killsnoopDesc = "Trace signals issued by the kill() syscall."
var loadsDesc = "Prints load averages."
var mdflushDesc = "Trace md flush events."
var naptimeDesc = "Show voluntary sleep calls."
var oomkillDesc = "Trace OOM killer."
var opensnoopDesc = "Trace open() syscalls."
var pidpersecDesc = "Count new procesess (via fork)."
var runqlatDesc = "CPU scheduler run queue latency as a histogram."
var runqlenDesc = "CPU scheduler run queue length as a histogram."
var setuidsDesc = "Trace the setuid syscalls: privilege escalation."
var statsnoopDesc = "Trace stat() syscalls."
var swapinDesc = "Show swapins by process."
var syncsnoopDesc = "Trace sync() variety of syscalls."
var syscountDesc = "Count system calls."
var tcpacceptDesc = "Trace TCP accept()s"
var tcpconnectDesc = "Trace TCP connect()s."
var tcpdropDesc = "Trace TCP kernel-dropped packets/segments."
var tcplifeDesc = "Trace TCP session lifespans with connection details."
var tcpretransDesc = "Trace or count TCP retransmits"
var tcpsynblDesc = "Show TCP SYN backlog as a histogram."
var threadsnoopDesc = "List new thread creation."
var vfscountDesc = "Count VFS calls (\"vfs_*\")."
var vfsstatDesc = "Count some VFS calls, with per-second summaries."
var writebackDesc = "Trace file system writeback events with details."
var xfsdistDesc = "Summarize XFS operation latency."

var bashreadline = `#!/usr/bin/env bpftrace
/*
 * bashreadline    Print entered bash commands from all running shells.
 *                 For Linux, uses bpftrace and eBPF.
 *
 * This works by tracing the readline() function using a uretprobe (uprobes).
 *
 * USAGE: bashreadline.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var bashreadline_example = `Demonstrations of bashreadline, the Linux bpftrace/eBPF version.


This prints bash commands from all running bash shells on the system. For
example:

# ./bashreadline.bt
Attaching 2 probes...
Tracing bash commands... Hit Ctrl-C to end.
TIME      PID    COMMAND
06:40:06  5526   df -h
06:40:09  5526   ls -l
06:40:18  5526   echo hello bpftrace
06:40:42  5526   echooo this is a failed command, but we can see it anyway
^C

The entered command may fail. This is just showing what command lines were
entered interactively for bash to process.

It works by tracing the return of the readline() function using uprobes
(specifically a uretprobe).


There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var biolatency = `#!/usr/bin/env bpftrace
/*
 * biolatency.bt	Block I/O latency as a histogram.
 *			For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var biolatency_example = `Demonstrations of biolatency, the Linux BPF/bpftrace version.


This traces block I/O, and shows latency as a power-of-2 histogram. For example:

# ./biolatency.bt
Attaching 3 probes...
Tracing block device I/O... Hit Ctrl-C to end.
^C

@usecs:
[256, 512)             2 |                                                    |
[512, 1K)             10 |@                                                   |
[1K, 2K)             426 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2K, 4K)             230 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        |
[4K, 8K)               9 |@                                                   |
[8K, 16K)            128 |@@@@@@@@@@@@@@@                                     |
[16K, 32K)            68 |@@@@@@@@                                            |
[32K, 64K)             0 |                                                    |
[64K, 128K)            0 |                                                    |
[128K, 256K)          10 |@                                                   |

While tracing, this shows that 426 block I/O had a latency of between 1K and 2K
usecs (1024 and 2048 microseconds), which is between 1 and 2 milliseconds.
There are also two modes visible, one between 1 and 2 milliseconds, and another
between 8 and 16 milliseconds: this sounds like cache hits and cache misses.
There were also 10 I/O with latency 128 to 256 ms: outliers. Other tools and
instrumentation, like biosnoop.bt, can shed more light on those outliers.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
var biosnoop = `#!/usr/bin/env bpftrace
/*
 * biosnoop.bt   Block I/O tracing tool, showing per I/O latency.
 *               For Linux, uses bpftrace, eBPF.
 *
 * TODO: switch to block tracepoints. Add device, offset, and size columns.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var biosnoop_example = `Demonstrations of biosnoop, the Linux BPF/bpftrace version.


This traces block I/O, and shows the issuing process (at least, the process
that was on-CPU at the time of queue insert) and the latency of the I/O:

# ./biosnoop.bt
Attaching 4 probes...
TIME(ms)     COMM             PID    LAT(ms)
611          bash             4179        10
611          cksum            4179         0
627          cksum            4179        15
641          cksum            4179        13
644          cksum            4179         3
658          cksum            4179        13
673          cksum            4179        14
686          cksum            4179        13
701          cksum            4179        14
710          cksum            4179         8
717          cksum            4179         6
728          cksum            4179        10
735          cksum            4179         6
751          cksum            4179        10
758          cksum            4179        17
783          cksum            4179        12
796          cksum            4179        25
802          cksum            4179        32
[...]

This output shows the cksum process was issuing block I/O, which were
completing with around 12 milliseconds of latency. Each block I/O event is
printed out, with a completion time as the first column, measured from
program start.


An example of some background flushing:

# ./biosnoop.bt
Attaching 4 probes...
TIME(ms)     COMM             PID    LAT(ms)
2966         jbd2/nvme0n1-8   615          0
2967         jbd2/nvme0n1-8   615          0
[...]


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides more fields.`
var biostacks = `#!/usr/local/bin/bpftrace
/*
 * biostacks - Show disk I/O latency with initialization stacks.
 *
 * See BPF Performance Tools, Chapter 9, for an explanation of this tool.
 *
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
var biostacks_example = `Demonstrations of biostacks, the Linux BCC/eBPF version.


This tool shows block I/O latency as a histogram, with the kernel stack trace
that initiated the I/O. This can help explain disk I/O that is not directly
requested by applications (eg, metadata reads on writes, resilvering, etc).
For example:

# ./biostacks.bt 
Attaching 5 probes...
Tracing block I/O with init stacks. Hit Ctrl-C to end.
^C

@usecs[
    blk_account_io_start+1
    blk_mq_make_request+1102
    generic_make_request+292
    submit_bio+115
    _xfs_buf_ioapply+798
    xfs_buf_submit+101
    xlog_bdstrat+43
    xlog_sync+705
    xlog_state_release_iclog+108
    _xfs_log_force+542
    xfs_log_force+44
    xfsaild+428
    kthread+289
    ret_from_fork+53
]: 
[64K, 128K)            1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

[...]

@usecs[
    blk_account_io_start+1
    blk_mq_make_request+707
    generic_make_request+292
    submit_bio+115
    xfs_add_to_ioend+455
    xfs_do_writepage+758
    write_cache_pages+524
    xfs_vm_writepages+190
    do_writepages+75
    __writeback_single_inode+69
    writeback_sb_inodes+481
    __writeback_inodes_wb+103
    wb_writeback+625
    wb_workfn+384
    process_one_work+478
    worker_thread+50
    kthread+289
    ret_from_fork+53
]: 
[8K, 16K)            560 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[16K, 32K)           218 |@@@@@@@@@@@@@@@@@@@@                                |
[32K, 64K)            26 |@@                                                  |
[64K, 128K)            2 |                                                    |
[128K, 256K)          53 |@@@@                                                |
[256K, 512K)          60 |@@@@@                                               |

This output shows the most frequent stack was XFS writeback, with latencies
between 8 and 512 microseconds. The other stack included here shows an XFS
log sync.`
var bitesize = `#!/usr/bin/env bpftrace
/*
 * bitesize	Show disk I/O size as a histogram.
 *		For Linux, uses bpftrace and eBPF.
 *
 * USAGE: bitesize.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
	printf("
I/O size (bytes) histograms by process name:");
}`
var bitesize_example = `Demonstrations of bitesize, the Linux bpftrace/eBPF version.


This traces disk I/O via the block I/O interface, and prints a summary of I/O
sizes as histograms for each process name. For example:

# ./bitesize.bt
Attaching 3 probes...
Tracing block device I/O... Hit Ctrl-C to end.
^C
I/O size (bytes) histograms by process name:

@[cleanup]:
[4K, 8K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@[postdrop]:
[4K, 8K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@[jps]:
[4K, 8K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[8K, 16K)              0 |                                                    |
[16K, 32K)             0 |                                                    |
[32K, 64K)             2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@[kworker/2:1H]:
[0]                    3 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1]                    0 |                                                    |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)               0 |                                                    |
[64, 128)              0 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               0 |                                                    |
[4K, 8K)               0 |                                                    |
[8K, 16K)              0 |                                                    |
[16K, 32K)             0 |                                                    |
[32K, 64K)             0 |                                                    |
[64K, 128K)            1 |@@@@@@@@@@@@@@@@@                                   |

@[jbd2/nvme0n1-8]:
[4K, 8K)               3 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)              0 |                                                    |
[16K, 32K)             0 |                                                    |
[32K, 64K)             2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[64K, 128K)            1 |@@@@@@@@@@@@@@@@@                                   |

@[dd]:
[16K, 32K)           921 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

The most active process while tracing was "dd", which issues 921 I/O between
16 Kbytes and 32 Kbytes in size.


There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var capable = `#!/usr/bin/env bpftrace
/*
 * capable	Trace security capabilitiy checks (cap_capable()).
 *		For Linux, uses bpftrace and eBPF.
 *
 * USAGE: capable.bt
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
var capable_example = `Demonstrations of capable, the Linux bpftrace/eBPF version.


capable traces calls to the kernel cap_capable() function, which does security
capability checks, and prints details for each call. For example:

# ./capable.bt
TIME      UID    PID    COMM             CAP  NAME                 AUDIT
22:11:23  114    2676   snmpd            12   CAP_NET_ADMIN        1
22:11:23  0      6990   run              24   CAP_SYS_RESOURCE     1
22:11:23  0      7003   chmod            3    CAP_FOWNER           1
22:11:23  0      7003   chmod            4    CAP_FSETID           1
22:11:23  0      7005   chmod            4    CAP_FSETID           1
22:11:23  0      7005   chmod            4    CAP_FSETID           1
22:11:23  0      7006   chown            4    CAP_FSETID           1
22:11:23  0      7006   chown            4    CAP_FSETID           1
22:11:23  0      6990   setuidgid        6    CAP_SETGID           1
22:11:23  0      6990   setuidgid        6    CAP_SETGID           1
22:11:23  0      6990   setuidgid        7    CAP_SETUID           1
22:11:24  0      7013   run              24   CAP_SYS_RESOURCE     1
22:11:24  0      7026   chmod            3    CAP_FOWNER           1
22:11:24  0      7026   chmod            4    CAP_FSETID           1
22:11:24  0      7028   chmod            4    CAP_FSETID           1
22:11:24  0      7028   chmod            4    CAP_FSETID           1
22:11:24  0      7029   chown            4    CAP_FSETID           1
22:11:24  0      7029   chown            4    CAP_FSETID           1
22:11:24  0      7013   setuidgid        6    CAP_SETGID           1
22:11:24  0      7013   setuidgid        6    CAP_SETGID           1
22:11:24  0      7013   setuidgid        7    CAP_SETUID           1
22:11:25  0      7036   run              24   CAP_SYS_RESOURCE     1
22:11:25  0      7049   chmod            3    CAP_FOWNER           1
22:11:25  0      7049   chmod            4    CAP_FSETID           1
22:11:25  0      7051   chmod            4    CAP_FSETID           1
22:11:25  0      7051   chmod            4    CAP_FSETID           1
[...]

This can be useful for general debugging, and also security enforcement:
determining a whitelist of capabilities an application needs.

The output above includes various capability checks: snmpd checking
CAP_NET_ADMIN, run checking CAP_SYS_RESOURCES, then some short-lived processes
checking CAP_FOWNER, CAP_FSETID, etc.

To see what each of these capabilities does, check the capabilities(7) man
page and the kernel source.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
var CMakeLists = `file(GLOB BT_FILES *.bt)
file(GLOB TXT_FILES *)
list(REMOVE_ITEM TXT_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists)
install(FILES ${BT_FILES} DESTINATION share/bpftrace/tools)
install(FILES ${TXT_FILES} DESTINATION share/bpftrace/tools/doc)`
var cpuwalk = `#!/usr/bin/env bpftrace
/*
 * cpuwalk	Sample which CPUs are executing processes.
 *		For Linux, uses bpftrace and eBPF.
 *
 * USAGE: cpuwalk.bt
 *
 * This is a bpftrace version of the DTraceToolkit tool of the same name.
 *
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
var cpuwalk_example = `Demonstrations of cpuwalk, the Linux bpftrace/eBPF version.


cpuwalk samples which CPUs processes are running on, and prints a summary
histogram. For example, here is a Linux kernel build on a 36-CPU server:

# ./cpuwalk.bt
Attaching 2 probes...
Sampling CPU at 99hz... Hit Ctrl-C to end.
^C

@cpu:
[0, 1)               130 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    |
[1, 2)               137 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  |
[2, 3)                99 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                |
[3, 4)                99 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                |
[4, 5)                82 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      |
[5, 6)                34 |@@@@@@@@@@@@                                        |
[6, 7)                67 |@@@@@@@@@@@@@@@@@@@@@@@@                            |
[7, 8)                41 |@@@@@@@@@@@@@@@                                     |
[8, 9)                97 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                |
[9, 10)              140 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[10, 11)             105 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             |
[11, 12)              77 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        |
[12, 13)              39 |@@@@@@@@@@@@@@                                      |
[13, 14)              58 |@@@@@@@@@@@@@@@@@@@@@                               |
[14, 15)              64 |@@@@@@@@@@@@@@@@@@@@@@@                             |
[15, 16)              57 |@@@@@@@@@@@@@@@@@@@@@                               |
[16, 17)              99 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                |
[17, 18)              56 |@@@@@@@@@@@@@@@@@@@@                                |
[18, 19)              44 |@@@@@@@@@@@@@@@@                                    |
[19, 20)              80 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                       |
[20, 21)              64 |@@@@@@@@@@@@@@@@@@@@@@@                             |
[21, 22)              59 |@@@@@@@@@@@@@@@@@@@@@                               |
[22, 23)              88 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    |
[23, 24)              84 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[24, 25)              29 |@@@@@@@@@@                                          |
[25, 26)              48 |@@@@@@@@@@@@@@@@@                                   |
[26, 27)              62 |@@@@@@@@@@@@@@@@@@@@@@@                             |
[27, 28)              66 |@@@@@@@@@@@@@@@@@@@@@@@@                            |
[28, 29)              57 |@@@@@@@@@@@@@@@@@@@@@                               |
[29, 30)              59 |@@@@@@@@@@@@@@@@@@@@@                               |
[30, 31)              56 |@@@@@@@@@@@@@@@@@@@@                                |
[31, 32)              23 |@@@@@@@@                                            |
[32, 33)              90 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                   |
[33, 34)              62 |@@@@@@@@@@@@@@@@@@@@@@@                             |
[34, 35)              39 |@@@@@@@@@@@@@@                                      |
[35, 36)              68 |@@@@@@@@@@@@@@@@@@@@@@@@@                           |

This shows that all 36 CPUs were active, with some busier than others.


Compare that output to the following workload from an application:

# ./cpuwalk.bt
Attaching 2 probes...
Sampling CPU at 99hz... Hit Ctrl-C to end.
^C

@cpu:
[6, 7)               243 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[7, 8)                 0 |                                                    |
[8, 9)                 0 |                                                    |
[9, 10)                0 |                                                    |
[10, 11)               0 |                                                    |
[11, 12)               0 |                                                    |
[12, 13)               0 |                                                    |
[13, 14)               0 |                                                    |
[14, 15)               0 |                                                    |
[15, 16)               0 |                                                    |
[16, 17)               0 |                                                    |
[17, 18)               0 |                                                    |
[18, 19)               0 |                                                    |
[19, 20)               0 |                                                    |
[20, 21)               1 |                                                    |

In this case, only a single CPU (6) is really active doing work. Only a single
sample was taken of another CPU (20) running a process. If the workload was
supposed to be making use of multiple CPUs, it isn't, and that can be
investigated (application's configuration, number of threads, CPU binding, etc).`
var dcsnoop = `#!/usr/bin/env bpftrace
/*
 * dcsnoop	Trace directory entry cache (dcache) lookups.
 *		For Linux, uses bpftrace and eBPF.
 *
 * This uses kernel dynamic tracing of kernel functions, lookup_fast() and
 * d_lookup(), which will need to be modified to match kernel changes. See
 * code comments.
 *
 * USAGE: dcsnoop.bt
 *
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
var dcsnoop_example = `Demonstrations of dcsnoop, the Linux bpftrace/eBPF version.


dcsnoop traces directory entry cache (dcache) lookups, and can be used for
further investigation beyond dcstat(8). The output is likely verbose, as
dcache lookups are likely frequent. For example:

# ./dcsnoop.bt
Attaching 4 probes...
Tracing dcache lookups... Hit Ctrl-C to end.
TIME     PID    COMM             T FILE
427      1518   irqbalance       R proc/interrupts
427      1518   irqbalance       R interrupts
427      1518   irqbalance       R proc/stat
427      1518   irqbalance       R stat
483      2440   snmp-pass        R proc/cpuinfo
483      2440   snmp-pass        R cpuinfo
486      2440   snmp-pass        R proc/stat
486      2440   snmp-pass        R stat
834      1744   snmpd            R proc/net/dev
834      1744   snmpd            R net/dev
834      1744   snmpd            R self/net
834      1744   snmpd            R 1744
834      1744   snmpd            R net
834      1744   snmpd            R dev
834      1744   snmpd            R proc/net/if_inet6
834      1744   snmpd            R net/if_inet6
834      1744   snmpd            R self/net
834      1744   snmpd            R 1744
834      1744   snmpd            R net
834      1744   snmpd            R if_inet6
835      1744   snmpd            R sys/class/net/docker0/device/vendor
835      1744   snmpd            R class/net/docker0/device/vendor
835      1744   snmpd            R net/docker0/device/vendor
835      1744   snmpd            R docker0/device/vendor
835      1744   snmpd            R devices/virtual/net/docker0
835      1744   snmpd            R virtual/net/docker0
835      1744   snmpd            R net/docker0
835      1744   snmpd            R docker0
835      1744   snmpd            R device/vendor
835      1744   snmpd            R proc/sys/net/ipv4/neigh/docker0/retrans_time_ms
835      1744   snmpd            R sys/net/ipv4/neigh/docker0/retrans_time_ms
835      1744   snmpd            R net/ipv4/neigh/docker0/retrans_time_ms
835      1744   snmpd            R ipv4/neigh/docker0/retrans_time_ms
835      1744   snmpd            R neigh/docker0/retrans_time_ms
835      1744   snmpd            R docker0/retrans_time_ms
835      1744   snmpd            R retrans_time_ms
835      1744   snmpd            R proc/sys/net/ipv6/neigh/docker0/retrans_time_ms
835      1744   snmpd            R sys/net/ipv6/neigh/docker0/retrans_time_ms
835      1744   snmpd            R net/ipv6/neigh/docker0/retrans_time_ms
835      1744   snmpd            R ipv6/neigh/docker0/retrans_time_ms
835      1744   snmpd            R neigh/docker0/retrans_time_ms
835      1744   snmpd            R docker0/retrans_time_ms
835      1744   snmpd            R retrans_time_ms
835      1744   snmpd            R proc/sys/net/ipv6/conf/docker0/forwarding
835      1744   snmpd            R sys/net/ipv6/conf/docker0/forwarding
835      1744   snmpd            R net/ipv6/conf/docker0/forwarding
835      1744   snmpd            R ipv6/conf/docker0/forwarding
835      1744   snmpd            R conf/docker0/forwarding
[...]
5154     934    cksum            R usr/bin/basename
5154     934    cksum            R bin/basename
5154     934    cksum            R basename
5154     934    cksum            R usr/bin/bashbug
5154     934    cksum            R bin/bashbug
5154     934    cksum            R bashbug
5154     934    cksum            M bashbug
5155     934    cksum            R usr/bin/batch
5155     934    cksum            R bin/batch
5155     934    cksum            R batch
5155     934    cksum            M batch
5155     934    cksum            R usr/bin/bc
5155     934    cksum            R bin/bc
5155     934    cksum            R bc
5155     934    cksum            M bc
5169     934    cksum            R usr/bin/bdftopcf
5169     934    cksum            R bin/bdftopcf
5169     934    cksum            R bdftopcf
5169     934    cksum            M bdftopcf
5173     934    cksum            R usr/bin/bdftruncate
5173     934    cksum            R bin/bdftruncate
5173     934    cksum            R bdftruncate
5173     934    cksum            M bdftruncate

The way the dcache is currently implemented, each component of a path is
checked in turn. The first line, showing "proc/interrupts" from irqbalance,
will be a lookup for "proc" in a directory (that isn't shown here). If it
finds "proc", it will then lookup "interrupts" inside net.

The script is easily modifiable to only show misses, reducing the volume of
the output. Or use the bcc version of this tool, which only shows misses by
default: https://github.com/iovisor/bcc`
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
var execsnoop_example = `Demonstrations of execsnoop, the Linux BPF/bpftrace version.


Tracing all new process execution (via exec()):

# ./execsnoop.bt
Attaching 3 probes...
TIME(ms)   PID   ARGS
2460       3466  ls --color=auto -lh execsnoop.bt execsnoop.bt.0 execsnoop.bt.1
3996       3467  man ls
4005       3473  preconv -e UTF-8
4005       3473  preconv -e UTF-8
4005       3473  preconv -e UTF-8
4005       3473  preconv -e UTF-8
4005       3473  preconv -e UTF-8
4005       3474  tbl
4005       3474  tbl
4005       3474  tbl
4005       3474  tbl
4005       3474  tbl
4005       3476  nroff -mandoc -rLL=193n -rLT=193n -Tutf8
4005       3476  nroff -mandoc -rLL=193n -rLT=193n -Tutf8
4005       3476  nroff -mandoc -rLL=193n -rLT=193n -Tutf8
4005       3476  nroff -mandoc -rLL=193n -rLT=193n -Tutf8
4005       3476  nroff -mandoc -rLL=193n -rLT=193n -Tutf8
4006       3479  pager  -rLL=193n
4006       3479  pager  -rLL=193n
4006       3479  pager  -rLL=193n
4006       3479  pager  -rLL=193n
4006       3479  pager  -rLL=193n
4007       3481  locale charmap
4008       3482  groff -mtty-char -Tutf8 -mandoc -rLL=193n -rLT=193n
4009       3483  troff -mtty-char -mandoc -rLL=193n -rLT=193n -Tutf8

The output begins by showing an "ls" command, and then the process execution
to serve "man ls". The same exec arguments appear multiple times: in this case
they are failing as the $PATH variable is walked, until one finally succeeds.

This tool can be used to discover unwanted short-lived processes that may be
causing performance issues such as latency perturbations.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides more fields and command line options.`
var gethostlatency = `#!/usr/bin/env bpftrace
/*
 * gethostlatency	Trace getaddrinfo/gethostbyname[2] calls.
 *			For Linux, uses bpftrace and eBPF.
 *
 * This can be useful for identifying DNS latency, by identifying which
 * remote host name lookups were slow, and by how much.
 *
 * This uses dynamic tracing of user-level functions and registers, and may
 # need modifications to match your software and processor architecture.
 *
 * USAGE: gethostlatency.bt
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
var gethostlatency_example = `Demonstrations of gethostlatency, the Linux bpftrace/eBPF version.


This traces host name lookup calls (getaddrinfo(), gethostbyname(), and
gethostbyname2()), and shows the PID and command performing the lookup, the
latency (duration) of the call in milliseconds, and the host string:

# ./gethostlatency.bt
Attaching 7 probes...
Tracing getaddr/gethost calls... Hit Ctrl-C to end.
TIME      PID    COMM              LATms HOST
02:52:05  19105  curl                 81 www.netflix.com
02:52:12  19111  curl                 17 www.netflix.com
02:52:19  19116  curl                  9 www.facebook.com
02:52:23  19118  curl                  3 www.facebook.com

In this example, the first call to lookup "www.netflix.com" took 81 ms, and
the second took 17 ms (sounds like some caching).


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
var killsnoop = `#!/usr/bin/env bpftrace
/*
 * killsnoop	Trace signals issued by the kill() syscall.
 *		For Linux, uses bpftrace and eBPF.
 *
 * USAGE: killsnoop.bt
 *
 * Also a basic example of bpftrace.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var killsnoop_example = `Demonstrations of killsnoop, the Linux bpftrace/eBPF version.



This traces signals sent via the kill() syscall. For example:

# ./killsnoop.bt
Attaching 3 probes...
Tracing kill() signals... Hit Ctrl-C to end.
TIME      PID    COMM             SIG  TPID   RESULT
00:09:37  22485  bash             2    23856  0
00:09:40  22485  bash             2    23856  -3
00:09:31  22485  bash             15   23814  -3

The first line showed a SIGINT (2) sent from PID 22485 (a bash shell) to
PID 23856. The result, 0, means success. The next line shows the same signal
sent, which resulted in -3, a failure (likely because the target process
no longer existed).


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides command line options to customize the output.`
var loads = `#!/usr/bin/env bpftrace
/*
 * loads	Prints load averages.
 *		For Linux, uses bpftrace and eBPF.
 *
 * These are the same load averages printed by "uptime", but to three decimal
 * places instead of two (not that it really matters). This is really a
 * demonstration of fetching and processing a kernel structure from bpftrace.
 *
 * USAGE: loads.bt
 *
 * This is a bpftrace version of a DTraceToolkit tool.
 *
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
var loads_example = `Demonstrations of loads, the Linux bpftrace/eBPF version.


This is a simple tool that prints the system load averages, to three decimal
places each (not that it really matters), as a demonstration of fetching
kernel structures from bpftrace:

# ./loads.bt
Attaching 2 probes...
Reading load averages... Hit Ctrl-C to end.
21:29:17 load averages: 2.091 2.048 1.947
21:29:18 load averages: 2.091 2.048 1.947
21:29:19 load averages: 2.091 2.048 1.947
21:29:20 load averages: 2.091 2.048 1.947
21:29:21 load averages: 2.164 2.064 1.953
21:29:22 load averages: 2.164 2.064 1.953
21:29:23 load averages: 2.164 2.064 1.953
^C

These are the same load averages printed by uptime:

# uptime
 21:29:24 up 2 days, 18:57,  3 users,  load average: 2.16, 2.06, 1.95


For more on load averages, see my post:
http://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html`
var mdflush = `#!/usr/bin/env bpftrace
/*
 * mdflush	Trace md flush events.
 *		For Linux, uses bpftrace and eBPF.
 *
 * USAGE: mdflush.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var mdflush_example = `Demonstrations of mdflush, the Linux bpftrace/eBPF version.


The mdflush tool traces flushes at the md driver level, and prints details
including the time of the flush:

# ./mdflush.bt
Tracing md flush requests... Hit Ctrl-C to end.
TIME     PID    COMM             DEVICE
03:13:49 16770  sync             md0
03:14:08 16864  sync             md0
03:14:49 496    kworker/1:0H     md0
03:14:49 488    xfsaild/md0      md0
03:14:54 488    xfsaild/md0      md0
03:15:00 488    xfsaild/md0      md0
03:15:02 85     kswapd0          md0
03:15:02 488    xfsaild/md0      md0
03:15:05 488    xfsaild/md0      md0
03:15:08 488    xfsaild/md0      md0
03:15:10 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:12 488    xfsaild/md0      md0
03:15:13 488    xfsaild/md0      md0
03:15:15 488    xfsaild/md0      md0
03:15:19 496    kworker/1:0H     md0
03:15:49 496    kworker/1:0H     md0
03:15:55 18840  sync             md0
03:16:49 496    kworker/1:0H     md0
03:17:19 496    kworker/1:0H     md0
03:20:19 496    kworker/1:0H     md0
03:21:19 496    kworker/1:0H     md0
03:21:49 496    kworker/1:0H     md0
03:25:19 496    kworker/1:0H     md0
[...]

This can be useful for correlation with latency outliers or spikes in disk
latency, as measured using another tool (eg, system monitoring). If spikes in
disk latency often coincide with md flush events, then it would make flushing
a target for tuning.

Note that the flush events are likely to originate from higher in the I/O
stack, such as from file systems. This traces md processing them, and the
timestamp corresponds with when md began to issue the flush to disks.

There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var naptime = `#!/usr/local/bin/bpftrace
/*
 * naptime - Show voluntary sleep calls.
 *
 * See BPF Performance Tools, Chapter 13, for an explanation of this tool.
 *
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
var naptime_example = `Demonstrations of naptime, the Linux bpftrace/eBPF version.


Tracing application sleeps via the nanosleep(2) syscall:

# ./naptime.bt
Attaching 2 probes...
Tracing sleeps. Hit Ctrl-C to end.
TIME     PCOMM  PPID             COMM   PID              SECONDS
15:50:00 1      systemd          1319   mysqld           1.000
15:50:01 4388   bash             25250  sleep            5.000
15:50:01 1      systemd          1319   mysqld           1.000
15:50:01 1      systemd          1180   cron             60.000
15:50:01 1      systemd          1180   cron             60.000
15:50:02 1      systemd          1319   mysqld           1.000
[...]

The output shows mysqld performing a one second sleep every second (likely
a daemon thread), a sleep(1) command sleeping for five seconds and called
by bash, and cron threads sleeping for 60 seconds.`
var oomkill = `#!/usr/bin/env bpftrace
/*
 * oomkill	Trace OOM killer.
 *		For Linux, uses bpftrace and eBPF.
 *
 * This traces the kernel out-of-memory killer, and prints basic details,
 * including the system load averages. This can provide more context on the
 * system state at the time of OOM: was it getting busier or steady, based
 * on the load averages? This tool may also be useful to customize for
 * investigations; for example, by adding other task_struct details at the
 * time of the OOM, or other commands in the system() call.
 *
 * This currently works by using kernel dynamic tracing of oom_kill_process().
 *
 * USAGE: oomkill.bt
 *
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
var oomkill_example = `Demonstrations of oomkill, the Linux bpftrace/eBPF version.


oomkill is a simple program that traces the Linux out-of-memory (OOM) killer,
and shows basic details on one line per OOM kill:

# ./oomkill.bt
Tracing oom_kill_process()... Ctrl-C to end.
21:03:39 Triggered by PID 3297 ("ntpd"), OOM kill of PID 22516 ("perl"), 3850642 pages, loadavg: 0.99 0.39 0.30 3/282 22724
21:03:48 Triggered by PID 22517 ("perl"), OOM kill of PID 22517 ("perl"), 3850642 pages, loadavg: 0.99 0.41 0.30 2/282 22932

The first line shows that PID 22516, with process name "perl", was OOM killed
when it reached 3850642 pages (usually 4 Kbytes per page). This OOM kill
happened to be triggered by PID 3297, process name "ntpd", doing some memory
allocation.

The system log (dmesg) shows pages of details and system context about an OOM
kill. What it currently lacks, however, is context on how the system had been
changing over time. I've seen OOM kills where I wanted to know if the system
was at steady state at the time, or if there had been a recent increase in
workload that triggered the OOM event. oomkill provides some context: at the
end of the line is the load average information from /proc/loadavg. For both
of the oomkills here, we can see that the system was getting busier at the
time (a higher 1 minute "average" of 0.99, compared to the 15 minute "average"
of 0.30).

oomkill can also be the basis of other tools and customizations. For example,
you can edit it to include other task_struct details from the target PID at
the time of the OOM kill, or to run other commands from the shell.

There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var opensnoop = `#!/usr/bin/env bpftrace
/*
 * opensnoop	Trace open() syscalls.
 *		For Linux, uses bpftrace and eBPF.
 *
 * Also a basic example of bpftrace.
 *
 * USAGE: opensnoop.bt
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
var opensnoop_example = `Demonstrations of opensnoop, the Linux bpftrace/eBPF version.


opensnoop traces the open() syscall system-wide, and prints various details.
Example output:

# ./opensnoop.bt
Attaching 3 probes...
Tracing open syscalls... Hit Ctrl-C to end.
PID    COMM               FD ERR PATH
2440   snmp-pass           4   0 /proc/cpuinfo
2440   snmp-pass           4   0 /proc/stat
25706  ls                  3   0 /etc/ld.so.cache
25706  ls                  3   0 /lib/x86_64-linux-gnu/libselinux.so.1
25706  ls                  3   0 /lib/x86_64-linux-gnu/libc.so.6
25706  ls                  3   0 /lib/x86_64-linux-gnu/libpcre.so.3
25706  ls                  3   0 /lib/x86_64-linux-gnu/libdl.so.2
25706  ls                  3   0 /lib/x86_64-linux-gnu/libpthread.so.0
25706  ls                  3   0 /proc/filesystems
25706  ls                  3   0 /usr/lib/locale/locale-archive
25706  ls                  3   0 .
1744   snmpd               8   0 /proc/net/dev
1744   snmpd              21   0 /proc/net/if_inet6
1744   snmpd              21   0 /sys/class/net/eth0/device/vendor
1744   snmpd              21   0 /sys/class/net/eth0/device/device
1744   snmpd              21   0 /proc/sys/net/ipv4/neigh/eth0/retrans_time_ms
1744   snmpd              21   0 /proc/sys/net/ipv6/neigh/eth0/retrans_time_ms
1744   snmpd              21   0 /proc/sys/net/ipv6/conf/eth0/forwarding
1744   snmpd              21   0 /proc/sys/net/ipv6/neigh/eth0/base_reachable_time_ms
1744   snmpd              -1   2 /sys/class/net/lo/device/vendor
1744   snmpd              21   0 /proc/sys/net/ipv4/neigh/lo/retrans_time_ms
1744   snmpd              21   0 /proc/sys/net/ipv6/neigh/lo/retrans_time_ms
1744   snmpd              21   0 /proc/sys/net/ipv6/conf/lo/forwarding
1744   snmpd              21   0 /proc/sys/net/ipv6/neigh/lo/base_reachable_time_ms
2440   snmp-pass           4   0 /proc/cpuinfo
2440   snmp-pass           4   0 /proc/stat
22884  pickup             12   0 maildrop
2440   snmp-pass           4   0 /proc/cpuinfo
2440   snmp-pass           4   0 /proc/stat

While tracing, at "ls" command was launched: the libraries it uses can be seen
as they were opened. Also, the snmpd process opened various /proc and /sys
files (reading metrics).
was starting up: a new process).

opensnoop can be useful for discovering configuration and log files, if used
during application startup.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides command line options to customize the output.`
var pidpersec = `#!/usr/bin/env bpftrace
/*
 * pidpersec	Count new procesess (via fork).
 *		For Linux, uses bpftrace and eBPF.
 *
 * Written as a basic example of counting on an event.
 *
 * USAGE: pidpersec.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var pidpersec_example = `Demonstrations of pidpersec, the Linux bpftrace/eBPF version.


Tracing new procesess:

# ./pidpersec.bt
Attaching 4 probes...
Tracing new processes... Hit Ctrl-C to end.
22:29:50 PIDs/sec: @: 121
22:29:51 PIDs/sec: @: 120
22:29:52 PIDs/sec: @: 122
22:29:53 PIDs/sec: @: 124
22:29:54 PIDs/sec: @: 123
22:29:55 PIDs/sec: @: 121
22:29:56 PIDs/sec: @: 121
22:29:57 PIDs/sec: @: 121
22:29:58 PIDs/sec: @: 49
22:29:59 PIDs/sec:
22:30:00 PIDs/sec:
22:30:01 PIDs/sec:
22:30:02 PIDs/sec:
^C

The output begins by showing a rate of new procesess over 120 per second.
That then ends at time 22:29:59, and for the next few seconds there are zero
new processes per second.


The following example shows a Linux build launched at 6:33:40, on a 36 CPU
server, with make -j36:

# ./pidpersec.bt
Attaching 4 probes...
Tracing new processes... Hit Ctrl-C to end.
06:33:38 PIDs/sec:
06:33:39 PIDs/sec:
06:33:40 PIDs/sec: @: 2314
06:33:41 PIDs/sec: @: 2517
06:33:42 PIDs/sec: @: 1345
06:33:43 PIDs/sec: @: 1752
06:33:44 PIDs/sec: @: 1744
06:33:45 PIDs/sec: @: 1549
06:33:46 PIDs/sec: @: 1643
06:33:47 PIDs/sec: @: 1487
06:33:48 PIDs/sec: @: 1534
06:33:49 PIDs/sec: @: 1279
06:33:50 PIDs/sec: @: 1392
06:33:51 PIDs/sec: @: 1556
06:33:52 PIDs/sec: @: 1580
06:33:53 PIDs/sec: @: 1944

A Linux kernel build involves launched many thousands of short-lived processes,
which can be seen in the above output: a rate of over 1,000 processes per
second.


There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var runqlat = `#!/usr/bin/env bpftrace
/*
 * runqlat.bt	CPU scheduler run queue latency as a histogram.
 *		For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var runqlat_example = `Demonstrations of runqlat, the Linux BPF/bpftrace version.


This traces time spent waiting in the CPU scheduler for a turn on-CPU. This
metric is often called run queue latency, or scheduler latency. This tool shows
this latency as a power-of-2 histogram in nanoseconds. For example:

# ./runqlat.bt
Attaching 5 probes...
Tracing CPU scheduler... Hit Ctrl-C to end.
^C



@usecs:
[0]                    1 |                                                    |
[1]                   11 |@@                                                  |
[2, 4)                16 |@@@                                                 |
[4, 8)                43 |@@@@@@@@@@                                          |
[8, 16)              134 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[16, 32)             220 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[32, 64)             117 |@@@@@@@@@@@@@@@@@@@@@@@@@@@                         |
[64, 128)             84 |@@@@@@@@@@@@@@@@@@@                                 |
[128, 256)            10 |@@                                                  |
[256, 512)             2 |                                                    |
[512, 1K)              5 |@                                                   |
[1K, 2K)               5 |@                                                   |
[2K, 4K)               5 |@                                                   |
[4K, 8K)               4 |                                                    |
[8K, 16K)              1 |                                                    |
[16K, 32K)             2 |                                                    |
[32K, 64K)             0 |                                                    |
[64K, 128K)            1 |                                                    |
[128K, 256K)           0 |                                                    |
[256K, 512K)           0 |                                                    |
[512K, 1M)             1 |                                                    |

This is an idle system where most of the time we are waiting for less than
128 microseconds, shown by the mode above. As an example of reading the output,
the above histogram shows 220 scheduling events with a run queue latency of
between 16 and 32 microseconds.

The output also shows an outlier taking between 0.5 and 1 seconds: ??? XXX
likely work was scheduled behind another higher priority task, and had to wait
briefly. The kernel decides whether it is worth migrating such work to an
idle CPU, or leaving it wait its turn on its current CPU run queue where
the CPU caches should be hotter.


I'll now add a single-threaded CPU bound workload to this system, and bind
it on one CPU:

# ./runqlat.bt
Attaching 5 probes...
Tracing CPU scheduler... Hit Ctrl-C to end.
^C



@usecs:
[1]                    6 |@@@                                                 |
[2, 4)                26 |@@@@@@@@@@@@@                                       |
[4, 8)                97 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8, 16)               72 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              |
[16, 32)              17 |@@@@@@@@@                                           |
[32, 64)              19 |@@@@@@@@@@                                          |
[64, 128)             20 |@@@@@@@@@@                                          |
[128, 256)             3 |@                                                   |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               1 |                                                    |
[2K, 4K)               1 |                                                    |
[4K, 8K)               4 |@@                                                  |
[8K, 16K)              3 |@                                                   |
[16K, 32K)             0 |                                                    |
[32K, 64K)             0 |                                                    |
[64K, 128K)            0 |                                                    |
[128K, 256K)           1 |                                                    |
[256K, 512K)           0 |                                                    |
[512K, 1M)             0 |                                                    |
[1M, 2M)               1 |                                                    |

That didn't make much difference.


Now I'll add a second single-threaded CPU workload, and bind it to the same
CPU, causing contention:

# ./runqlat.bt
Attaching 5 probes...
Tracing CPU scheduler... Hit Ctrl-C to end.
^C



@usecs:
[0]                    1 |                                                    |
[1]                    8 |@@@                                                 |
[2, 4)                28 |@@@@@@@@@@@@                                        |
[4, 8)                95 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[8, 16)              120 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[16, 32)              22 |@@@@@@@@@                                           |
[32, 64)              10 |@@@@                                                |
[64, 128)              7 |@@@                                                 |
[128, 256)             3 |@                                                   |
[256, 512)             1 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               0 |                                                    |
[2K, 4K)               2 |                                                    |
[4K, 8K)               4 |@                                                   |
[8K, 16K)            107 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      |
[16K, 32K)             0 |                                                    |
[32K, 64K)             0 |                                                    |
[64K, 128K)            0 |                                                    |
[128K, 256K)           0 |                                                    |
[256K, 512K)           1 |                                                    |

There's now a second mode between 8 and 16 milliseconds, as each thread must
wait its turn on the one CPU.


Now I'l run 10 CPU-bound throuds on one CPU:

# ./runqlat.bt
Attaching 5 probes...
Tracing CPU scheduler... Hit Ctrl-C to end.
^C



@usecs:
[0]                    2 |                                                    |
[1]                   10 |@                                                   |
[2, 4)                38 |@@@@                                                |
[4, 8)                63 |@@@@@@                                              |
[8, 16)              106 |@@@@@@@@@@@                                         |
[16, 32)              28 |@@@                                                 |
[32, 64)              13 |@                                                   |
[64, 128)             15 |@                                                   |
[128, 256)             2 |                                                    |
[256, 512)             2 |                                                    |
[512, 1K)              1 |                                                    |
[1K, 2K)               1 |                                                    |
[2K, 4K)               2 |                                                    |
[4K, 8K)               4 |                                                    |
[8K, 16K)              3 |                                                    |
[16K, 32K)             0 |                                                    |
[32K, 64K)           478 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[64K, 128K)            1 |                                                    |
[128K, 256K)           0 |                                                    |
[256K, 512K)           0 |                                                    |
[512K, 1M)             0 |                                                    |
[1M, 2M)               1 |                                                    |

This shows that most of the time threads need to wait their turn, with the
largest mode between 32 and 64 milliseconds.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
var runqlen = `#!/usr/bin/env bpftrace
/*
 * runqlen.bt	CPU scheduler run queue length as a histogram.
 *		For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var runqlen_example = `Demonstrations of runqlen, the Linux BPF/bpftrace version.


This tool samples the length of the CPU scheduler run queues, showing these
sampled lengths as a histogram. This can be used to characterize demand for
CPU resources. For example:

# ./runqlen.bt 
Attaching 2 probes...
Sampling run queue length at 99 Hertz... Hit Ctrl-C to end.
^C

@runqlen: 
[0, 1)              1967 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1, 2)                 0 |                                                    |
[2, 3)                 0 |                                                    |
[3, 4)               306 |@@@@@@@@                                            |

This output shows that the run queue length was usually zero, except for some
samples where it was 3. This was caused by binding 4 CPU bound threads to a
single CPUs.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
var setuids = `#!/usr/local/bin/bpftrace
/*
 * setuids - Trace the setuid syscalls: privilege escalation.
 *
 * See BPF Performance Tools, Chapter 11, for an explanation of this tool.
 *
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
var setuids_example = `Demonstrations of setuids, the Linux bpftrace/eBPF version.


This tool traces privilege escalation via setuid syscalls (setuid(2),
setfsuid(2), retresuid(2)). For example, here are the setuid calls during an
ssh login:

# ./setuids.bt
Attaching 7 probes...
Tracing setuid(2) family syscalls. Hit Ctrl-C to end.
TIME     PID    COMM             UID    SYSCALL   ARGS (RET)
14:28:22 21785  ssh              1000   setresuid ruid=-1 euid=1000 suid=-1 (0)
14:28:22 21787  sshd             0      setresuid ruid=122 euid=122 suid=122 (0)
14:28:22 21787  sshd             122    setuid    uid=0 (-1)
14:28:22 21787  sshd             122    setresuid ruid=-1 euid=0 suid=-1 (-1)
14:28:24 21786  sshd             0      setresuid ruid=-1 euid=1000 suid=-1 (0)
14:28:24 21786  sshd             0      setresuid ruid=-1 euid=0 suid=-1 (0)
14:28:24 21786  sshd             0      setresuid ruid=-1 euid=1000 suid=-1 (0)
14:28:24 21786  sshd             0      setresuid ruid=-1 euid=0 suid=-1 (0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=0)
14:28:24 21786  sshd             0      setfsuid  uid=1000 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=1000)
14:28:24 21786  sshd             0      setfsuid  uid=0 (prevuid=0)
14:28:24 21851  sshd             0      setresuid ruid=1000 euid=1000 suid=1000 (0)
14:28:24 21851  sshd             1000   setuid    uid=0 (-1)
14:28:24 21851  sshd             1000   setresuid ruid=-1 euid=0 suid=-1 (-1)

Why does sshd make so many calls? I don't know! Nevertheless, this shows what
this tool can do: it shows the caller details (PID, COMM, and UID), the syscall
(SYSCALL), and the syscall arguments (ARGS) and return value (RET). You can
modify this tool to print user stack traces for each call, which will show the
code path in sshd (provided it is compiled with frame pointers).`
var statsnoop = `#!/usr/bin/env bpftrace
/*
 * statsnoop	Trace stat() syscalls.
 *		For Linux, uses bpftrace and eBPF.
 *
 * This traces the traecepoints for statfs(), statx(), newstat(), and
 * newlstat(). These aren't the only the stat syscalls: if you are missing
 * activity, you may need to add more variants.
 *
 * Also a basic example of bpftrace.
 *
 * USAGE: statsnoop.bt
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
var statsnoop_example = `Demonstrations of statsnoop, the Linux bpftrace/eBPF version.


statsnoop traces different stat() syscalls system-wide, and prints details.
Example output:

# ./statsnoop.bt
Attaching 9 probes...
Tracing stat syscalls... Hit Ctrl-C to end.
PID    COMM             ERR PATH
27835  bash               0 .
27835  bash               2 /usr/local/sbin/iconfig
27835  bash               2 /usr/local/bin/iconfig
27835  bash               2 /usr/sbin/iconfig
27835  bash               2 /usr/bin/iconfig
27835  bash               2 /sbin/iconfig
27835  bash               2 /bin/iconfig
27835  bash               2 /usr/games/iconfig
27835  bash               2 /usr/local/games/iconfig
27835  bash               2 /snap/bin/iconfig
27835  bash               2 /apps/python/bin/iconfig
30573  command-not-fou    2 /usr/bin/Modules/Setup
30573  command-not-fou    2 /usr/bin/lib/python3.5/os.py
30573  command-not-fou    2 /usr/bin/lib/python3.5/os.pyc
30573  command-not-fou    0 /usr/lib/python3.5/os.py
30573  command-not-fou    2 /usr/bin/pybuilddir
30573  command-not-fou    2 /usr/bin/lib/python3.5/lib-dynload
30573  command-not-fou    0 /usr/lib/python3.5/lib-dynload
30573  command-not-fou    2 /usr/lib/python35.zip
30573  command-not-fou    0 /usr/lib
30573  command-not-fou    2 /usr/lib/python35.zip
30573  command-not-fou    0 /usr/lib/python3.5/
30573  command-not-fou    0 /usr/lib/python3.5/
30573  command-not-fou    0 /usr/lib/python3.5/
30573  command-not-fou    2 /usr/lib/python3.5/encodings/__init__.cpython-35m-x86_64-linux-
30573  command-not-fou    2 /usr/lib/python3.5/encodings/__init__.abi3.so
30573  command-not-fou    2 /usr/lib/python3.5/encodings/__init__.so
30573  command-not-fou    0 /usr/lib/python3.5/encodings/__init__.py
30573  command-not-fou    0 /usr/lib/python3.5/encodings/__init__.py

This output has caught me mistyping a command in another shell, "iconfig"
instead of "ifconfig". The first several lines show the bash shell searching
the $PATH (why is games in my $PATH??), and failing to find it (ERR == 2 is
file not found). Then, a "command-not-found" program executes (the name is
truncated to 16 characters in the COMM field, including the NULL), which
begins the process of searching for and suggesting a package. ie, this:

# iconfig
The program 'iconfig' is currently not installed. You can install it by typing:
apt install ipmiutil

statsnoop can be used for general debugging, to see what file information has
been requested, and whether those files exist. It can be used as a companion
to opensnoop, which shows what files were actually opened.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides options to customize the output.`
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
var swapin_example = `Demonstrations of swapin, the Linux BCC/eBPF version.


This tool counts swapins by process, to show which process is affected by
swapping. For example:

# ./swapin.bt 
Attaching 2 probes...
13:36:59

13:37:00
@[chrome, 4536]: 10809
@[gnome-shell, 2239]: 12410

13:37:01
@[chrome, 4536]: 3826

13:37:02
@[cron, 1180]: 23
@[gnome-shell, 2239]: 2462

13:37:03
@[gnome-shell, 1444]: 4
@[gnome-shell, 2239]: 3420

13:37:04

13:37:05
[...]

While tracing, this showed that PID 2239 (gnome-shell) and PID 4536 (chrome)
suffered over ten thousand swapins.`
var syncsnoop = `#!/usr/bin/env bpftrace
/*
 * syncsnoop	Trace sync() variety of syscalls.
 *		For Linux, uses bpftrace and eBPF.
 *
 * Also a basic example of bpftrace.
 *
 * USAGE: syncsnoop.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var syncsnoop_example = `Demonstrations of syncsnoop, the Linux bpftrace/eBPF version.


Tracing file system sync events:

# ./syncsnoop.bt
Attaching 7 probes...
Tracing sync syscalls... Hit Ctrl-C to end.
TIME      PID    COMM             EVENT
02:02:17  27933  sync             tracepoint:syscalls:sys_enter_sync
02:03:43  27936  sync             tracepoint:syscalls:sys_enter_sync

The output shows calls to the sync() syscall (traced via its tracepoint),
along with various details.


There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var syscount = `#!/usr/bin/env bpftrace
/*
 * syscount.bt	Count system callls.
 *		For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 * The bcc versions translates syscall IDs to their names, and this version
 * currently does not. Syscall IDs can be listed by "ausyscall --dump".
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 13-Sep-2018	Brendan Gregg	Created this.
 */

BEGIN
{
	printf("Counting syscalls... Hit Ctrl-C to end.\n");
	// ausyscall --dump | awk 'NR > 1 { printf("	@sysname[%d] = \"%s\";\n", $1, $2); }'
}

tracepoint:raw_syscalls:sys_enter
{
	@syscall[args->id] = count();
	@process[comm] = count();
}

END
{
	printf("
Top 10 syscalls IDs:\n");
	print(@syscall, 10);
	clear(@syscall);

	printf("
Top 10 processes:\n");
	print(@process, 10);
	clear(@process);
}`
var syscount_example = `Demonstrations of syscount, the Linux bpftrace/eBPF version.


syscount counts system calls, and prints summaries of the top ten syscall IDs,
and the top ten process names making syscalls. For example:

# ./syscount.bt
Attaching 3 probes...
Counting syscalls... Hit Ctrl-C to end.
^C
Top 10 syscalls IDs:
@syscall[6]: 36862
@syscall[21]: 42189
@syscall[13]: 44532
@syscall[12]: 58456
@syscall[9]: 82113
@syscall[8]: 95575
@syscall[5]: 147658
@syscall[3]: 163269
@syscall[2]: 270801
@syscall[4]: 326333

Top 10 processes:
@process[rm]: 14360
@process[tail]: 16011
@process[objtool]: 20767
@process[fixdep]: 28489
@process[as]: 48982
@process[gcc]: 90652
@process[command-not-fou]: 172874
@process[sh]: 270515
@process[cc1]: 482888
@process[make]: 1404065

The above output was traced during a Linux kernel build, and the process name
with the most syscalls was "make" with 1,404,065 syscalls while tracing. The
highest syscall ID was 4, which is stat().


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides different command line options, and translates the
syscall IDs to their syscall names.`
var tcpaccept = `#!/usr/bin/env bpftrace
/*
 * tcpaccept.bt Trace TCP accept()s
 *              For Linux, uses bpftrace and eBPF.
 *
 * USAGE: tcpaccept.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * This uses dynamic tracing of the kernel inet_csk_accept() socket function
 * (from tcp_prot.accept), and will need to be modified to match kernel changes.

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
var tcpaccept_example = `Demonstrations of tcpaccept, the Linux bpftrace/eBPF version.


This tool traces the kernel function accepting TCP socket connections (eg, a
passive connection via accept(); not connect()). Some example output (IP
addresses changed to protect the innocent):

# ./tcpaccept.bt
Tracing tcp accepts. Hit Ctrl-C to end.
TIME     PID     COMM           RADDR          RPORT LADDR          LPORT BL
00:34:19 3949061 nginx          10.228.22.228  44226 10.229.20.169  8080  0/128
00:34:19 3951399 ruby           127.0.0.1      52422 127.0.0.1      8000  0/128
00:34:19 3949062 nginx          10.228.23.128  35408 10.229.20.169  8080  0/128


This output shows three connections, an IPv4 connections to PID 1463622, a "redis-server"
process listening on port 6379, and one IPv6 connection to a "thread.rb" process
listening on port 8000. The remote address and port are also printed, and the accept queue
current size as well as maximum size are shown.

The overhead of this tool should be negligible, since it is only tracing the
kernel function performing accept. It is not tracing every packet and then
filtering.

This tool only traces successful TCP accept()s. Connection attempts to closed
ports will not be shown (those can be traced via other functions).

There is another version of this tool in bcc: https://github.com/iovisor/bcc

USAGE message:

# ./tcpaccept.bt`
var tcpconnect = `#!/usr/bin/env bpftrace
/*
 * tcpconnect.bt  Trace TCP connect()s.
 *                For Linux, uses bpftrace and eBPF.
 *
 * USAGE: tcpconnect.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 * It is limited to ipv4 addresses.
 *
 * All connection attempts are traced, even if they ultimately fail.
 *
 * This uses dynamic tracing of kernel functions, and will need to be updated
 * to match kernel changes.
 *
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
var tcpconnect_example = `Demonstrations of tcpconnect, the Linux bpftrace/eBPF version.


This tool traces the kernel function performing active TCP connections
(eg, via a connect() syscall; accept() are passive connections). Some example
output (IP addresses changed to protect the innocent):

# ./tcpconnect.bt
TIME     PID      COMM             SADDR          SPORT  DADDR          DPORT
00:36:45 1798396  agent            127.0.0.1      5001   10.229.20.82   56114
00:36:45 1798396  curl             127.0.0.1      10255  10.229.20.82   56606
00:36:45 3949059  nginx            127.0.0.1      8000   127.0.0.1      37780


This output shows three connections, one from a "agent" process, one from\n"curl", and one from "redis-cli". The output details shows the IP version, source
address, source socket port, destination address, and destination port. This traces attempted
connections: these may have failed.

The overhead of this tool should be negligible, since it is only tracing the
kernel functions performing connect. It is not tracing every packet and then
filtering.

USAGE message:

# ./tcpconnect.bt`
var tcpdrop = `#!/usr/bin/env bpftrace
/*
 * tcpdrop.bt   Trace TCP kernel-dropped packets/segments.
 *              For Linux, uses bpftrace and eBPF.
 *
 * USAGE: tcpdrop.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 * It is limited to ipv4 addresses, and cannot show tcp flags.
 *
 * This provides information such as packet details, socket state, and kernel
 * stack trace for packets/segments that were dropped via tcp_drop().

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
var tcpdrop_example = `Demonstrations of tcpdrop, the Linux bpftrace/eBPF version.


tcpdrop prints details of TCP packets or segments that were dropped by the
kernel, including the kernel stack trace that led to the drop:

# ./tcpdrop.bt
TIME     PID      COMM             SADDR:SPORT           DADDR:DPORT           STATE
00:39:21 0        swapper/2         10.231.244.31:3306     10.229.20.82:50552  ESTABLISHE
	tcp_drop+0x1
	tcp_v4_do_rcv+0x135
	tcp_v4_rcv+0x9c7
	ip_local_deliver_finish+0x62
	ip_local_deliver+0x6f
	ip_rcv_finish+0x129
	ip_rcv+0x28f
	__netif_receive_skb_core+0x432
	__netif_receive_skb+0x18
	netif_receive_skb_internal+0x37
	napi_gro_receive+0xc5
	ena_clean_rx_irq+0x3c3
	ena_io_poll+0x33f
	net_rx_action+0x140
	__softirqentry_text_start+0xdf
	irq_exit+0xb6
	do_IRQ+0x82
	ret_from_intr+0x0
	native_safe_halt+0x6
	default_idle+0x20
	arch_cpu_idle+0x15
	default_idle_call+0x23
	do_idle+0x17f
	cpu_startup_entry+0x73
	rest_init+0xae
	start_kernel+0x4dc
	x86_64_start_reservations+0x24
	x86_64_start_kernel+0x74
	secondary_startup_64+0xa5
[...]

The last column shows the state of the TCP session.

This tool is useful for debugging high rates of drops, which can cause the
remote end to do timer-based retransmits, hurting performance.

USAGE:

# ./tcpdrop.bt`
var tcplife = `#!/usr/local/bin/bpftrace
/*
 * tcplife - Trace TCP session lifespans with connection details.
 *
 * See BPF Performance Tools, Chapter 10, for an explanation of this tool.
 *
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
var tcplife_example = `Demonstrations of tcplife, the Linux bpftrace/eBPF version.


This tool shows the lifespan of TCP sessions, including througphut statistics,
and for efficiency only instruments TCP state changes (rather than all packets).
For example:

# ./tcplife.bt
PID   COMM       LADDR           LPORT RADDR           RPORT TX_KB RX_KB MS
20976 ssh        127.0.0.1       56766 127.0.0.1       22         6 10584 3059
20977 sshd       127.0.0.1       22    127.0.0.1       56766  10584     6 3059
14519 monitord   127.0.0.1       44832 127.0.0.1       44444      0     0 0
4496  Chrome_IOT 7f00:6:5ea7::a00:0 42846 0:0:bb01::      443        0     3 12441
4496  Chrome_IOT 7f00:6:5aa7::a00:0 42842 0:0:bb01::      443        0     3 12436
4496  Chrome_IOT 7f00:6:62a7::a00:0 42850 0:0:bb01::      443        0     3 12436
4496  Chrome_IOT 7f00:6:5ca7::a00:0 42844 0:0:bb01::      443        0     3 12442
4496  Chrome_IOT 7f00:6:60a7::a00:0 42848 0:0:bb01::      443        0     3 12436
4496  Chrome_IOT 10.0.0.65       33342 54.241.2.241    443        0     3 10717
4496  Chrome_IOT 10.0.0.65       33350 54.241.2.241    443        0     3 10711
4496  Chrome_IOT 10.0.0.65       33352 54.241.2.241    443        0     3 10712
14519 monitord   127.0.0.1       44832 127.0.0.1       44444      0     0 0

The output begins with a localhost ssh connection, so both endpoints can be
seen: the ssh process (PID 20976) which received 10584 Kbytes, and the sshd
process (PID 20977) which transmitted 10584 Kbytes. This session lasted 3059
milliseconds. Other sessions can also be seen, including IPv6 connections.`
var tcpretrans = `#!/usr/bin/env bpftrace
/*
 * tcpretrans.bt Trace or count TCP retransmits
 *               For Linux, uses bpftrace and eBPF.
 *
 * USAGE: tcpretrans.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 * It is limited to ipv4 addresses, and doesn't support tracking TLPs.
 *
 * This uses dynamic tracing of kernel functions, and will need to be updated
 * to match kernel changes.
 *
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
var tcpretrans_example = `Demonstrations of tcpretrans, the Linux bpftrace/eBPF version.


This tool traces the kernel TCP retransmit function to show details of these
retransmits. For example:

# ./tcpretrans.bt
TIME     PID               LADDR:LPORT          RADDR:RPORT  STATE
00:43:54 0          10.229.20.82:46654    153.2.224.76:443    SYN_SENT
00:43:55 0           10.232.0.49:57678    10.229.20.99:24231  SYN_SENT
00:43:57 100       10.229.20.175:54224   10.201.76.122:443    ESTABLISHED
[...]

This output shows three TCP retransmits, the first two were for an IPv4
connection from 10.153.223.157 port 22 to 69.53.245.40 port 34619. The TCP
state was "ESTABLISHED" at the time of the retransmit. The on-CPU PID at the
time of the retransmit is printed, in this case 0 (the kernel, which will
be the case most of the time).

Retransmits are usually a sign of poor network health, and this tool is
useful for their investigation. Unlike using tcpdump, this tool has very
low overhead, as it only traces the retransmit function. It also prints
additional kernel details: the state of the TCP session at the time of the
retransmit.

USAGE message:

# ./tcpretrans.bt`
var tcpsynbl = `#!/usr/local/bin/bpftrace
/*
 * tcpsynbl - Show TCP SYN backlog as a histogram.
 *
 * See BPF Performance Tools, Chapter 10, for an explanation of this tool.
 *
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
	printf("
@backlog[backlog limit]: histogram of backlog size\n");
}`
var tcpsynbl_example = `Demonstrations of tcpsynbl, the Linux bpftrace/eBPF version.


This tool shows the TCP SYN backlog size during SYN arrival as a histogram.
This lets you see how close your applications are to hitting the backlog limit
and dropping SYNs (causing performance issues with SYN retransmits). For
example:

# ./tcpsynbl.bt 
Attaching 4 probes...
Tracing SYN backlog size. Ctrl-C to end.
^C
@backlog[backlog limit]: histogram of backlog size


@backlog[500]: 
[0]                 2266 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1]                    3 |                                                    |
[2, 4)                 1 |                                                    |

This output shows that for the backlog limit of 500, there were 2266 SYN
arrivals where the backlog was zero, three where the backlog was one, and
one where the backlog was either two or three. This indicates that we are
nowhere near this limit.`
var threadsnoop = `#!/usr/local/bin/bpftrace
/*
 * threadsnoop - List new thread creation.
 *
 * See BPF Performance Tools, Chapter 13, for an explanation of this tool.
 *
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
var threadsnoop_example = `Demonstrations of threadsnoop, the Linux bpftrace/eBPF version.


Tracing new threads via phtread_create():

# ./threadsnoop.bt
Attaching 2 probes...
TIME(ms)   PID    COMM             FUNC
1938       28549  dockerd          threadentry
1939       28549  dockerd          threadentry
1939       28549  dockerd          threadentry
1940       28549  dockerd          threadentry
1949       28549  dockerd          threadentry
1958       28549  dockerd          threadentry
1939       28549  dockerd          threadentry
1950       28549  dockerd          threadentry
2013       28579  docker-containe  0x562f30f2e710
2036       28549  dockerd          threadentry
2083       28579  docker-containe  0x562f30f2e710
2116       629    systemd-journal  0x7fb7114955c0
2116       629    systemd-journal  0x7fb7114955c0
[...]

The output shows a dockerd process creating several threads with the start
routine threadentry(), and docker-containe (truncated) and systemd-journal
also starting threads: in their cases, the function had no symbol information
available, so their addresses are printed in hex.`
var vfscount = `#!/usr/bin/env bpftrace
/*
 * vfscount	Count VFS calls ("vfs_*").
 *		For Linux, uses bpftrace and eBPF.
 *
 * Written as a basic example of counting kernel functions.
 *
 * USAGE: vfscount.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var vfscount_example = `Demonstrations of vfscount, the Linux bpftrace/eBPF version.


Tracing all VFS calls:

# ./vfscount.bt
Attaching 54 probes...
cannot attach kprobe, Invalid argument
Warning: could not attach probe kprobe:vfs_dedupe_get_page.isra.21, skipping.
Tracing VFS calls... Hit Ctrl-C to end.
^C

@[vfs_fsync_range]: 4
@[vfs_readlink]: 14
@[vfs_statfs]: 56
@[vfs_lock_file]: 60
@[vfs_write]: 276
@[vfs_statx]: 328
@[vfs_statx_fd]: 394
@[vfs_open]: 541
@[vfs_getattr]: 595
@[vfs_getattr_nosec]: 597
@[vfs_read]: 1113

While tracing, the vfs_read() call was the most frequent, occurring 1,113 times.

VFS is the Virtual File System: a kernel abstraction for file systems and other
resources that expose a file system interface. Much of VFS maps directly to the
syscall interface. Tracing VFS calls gives you a high level breakdown of the
kernel workload, and starting points for further investigation.

Notet that a warning was printed: "Warning: could not attach probe
kprobe:vfs_dedupe_get_page.isra.21": these are not currently instrumentable by
bpftrace/kprobes, so a warning is printed to let you know that they will be
missed.


There is another version of this tool in bcc: https://github.com/iovisor/bcc`
var vfsstat = `#!/usr/bin/env bpftrace
/*
 * vfsstat	Count some VFS calls, with per-second summaries.
 *		For Linux, uses bpftrace and eBPF.
 *
 * Written as a basic example of counting multiple events and printing a
 * per-second summary.
 *
 * USAGE: vfsstat.bt
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
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
var vfsstat_example = `Demonstrations of vfsstat, the Linux bpftrace/eBPF version.


This traces some common VFS calls (see the script for the list) and prints
per-second summaries.

# ./vfsstat.bt
Attaching 8 probes...
Tracing key VFS calls... Hit Ctrl-C to end.
21:30:38
@[vfs_write]: 1274
@[vfs_open]: 8675
@[vfs_read]: 11515

21:30:39
@[vfs_write]: 1155
@[vfs_open]: 8077
@[vfs_read]: 10398

21:30:40
@[vfs_write]: 1222
@[vfs_open]: 8554
@[vfs_read]: 11011

21:30:41
@[vfs_write]: 1230
@[vfs_open]: 8605
@[vfs_read]: 11077

21:30:42
@[vfs_write]: 1229
@[vfs_open]: 8591
@[vfs_read]: 11061

^C

Each second, a timestamp is printed ("HH:MM:SS") followed by common VFS
functions and the number of calls for that second. While tracing, the vfs_read()
kernel function was most frequent, occurring over 10,000 times per second.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides command line options.`
var writeback = `#!/usr/bin/env bpftrace
/*
 * writeback	Trace file system writeback events with details.
 * 		For Linux, uses bpftrace and eBPF.
 *
 * This traces when file system dirtied pages are flushed to disk by kernel
 * writeback, and prints details including when the event occurred, and the
 * duration of the event. This can be useful for correlating these times with
 * other performace problems, and if there is a match, it would be a clue
 * that the problem may be caused by writeback. How quickly the kernel does
 * writeback can be tuned: see the kernel docs, eg,
 * vm.dirty_writeback_centisecs.
 *
 * USAGE: writeback.bt
 *
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
var writeback_example = `Demonstrations of writeback, the Linux bpftrace/eBPF version.


This tool traces when the kernel writeback procedure is writing dirtied pages
to disk, and shows details such as the time, device numbers, reason for the
write back, and the duration. For example:

# ./writeback.bt
Attaching 4 probes...
Tracing writeback... Hit Ctrl-C to end.
TIME      DEVICE   PAGES    REASON           ms
23:28:47  259:1    15791    periodic         0.005
23:28:48  259:0    15792    periodic         0.004
23:28:52  259:1    15784    periodic         0.003
23:28:53  259:0    18682    periodic         0.003
23:28:55  259:0    41970    background       326.663
23:28:56  259:0    18418    background       332.689
23:28:56  259:0    60402    background       362.446
23:28:57  259:1    18230    periodic         0.005
23:28:57  259:1    65492    background       3.343
23:28:57  259:1    65492    background       0.002
23:28:58  259:0    36850    background       0.000
23:28:58  259:0    13298    background       597.198
23:28:58  259:0    55282    background       322.050
23:28:59  259:0    31730    background       336.031
23:28:59  259:0    8178     background       357.119
23:29:01  259:0    50162    background       1803.146
23:29:02  259:0    27634    background       1311.876
23:29:03  259:0    6130     background       331.599
23:29:03  259:0    50162    background       293.968
23:29:03  259:0    28658    background       284.946
23:29:03  259:0    7154     background       286.572
[...]

By looking a the timestamps and latency, it can be seen that the system was
not spending much time in writeback until 23:28:55, when "background"
writeback began, taking over 300 milliseconds per flush.

If timestamps of heavy writeback coincide with times when applications suffered
performance issues, that would be a clue that they are correlated and there
is contention for the disk devices. There are various ways to tune this:
eg, vm.dirty_writeback_centisecs.`
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
var xfsdist_example = `Demonstrations of xfsdist, the Linux bpftrace/eBPF version.


xfsdist traces XFS reads, writes, opens, and fsyncs, and summarizes their
latency as a power-of-2 histogram. For example:

# xfsdist.bt
Attaching 9 probes...
Tracing XFS operation latency... Hit Ctrl-C to end.
^C

@us[xfs_file_write_iter]:
[8, 16)                1 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[16, 32)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

@us[xfs_file_read_iter]:
[1]                  724 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2, 4)               137 |@@@@@@@@@                                           |
[4, 8)               143 |@@@@@@@@@@                                          |
[8, 16)               37 |@@                                                  |
[16, 32)              11 |                                                    |
[32, 64)              22 |@                                                   |
[64, 128)              7 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)           485 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[512, 1K)            149 |@@@@@@@@@@                                          |
[1K, 2K)              98 |@@@@@@@                                             |
[2K, 4K)              85 |@@@@@@                                              |
[4K, 8K)              27 |@                                                   |
[8K, 16K)             29 |@@                                                  |
[16K, 32K)            25 |@                                                   |
[32K, 64K)             1 |                                                    |
[64K, 128K)            0 |                                                    |
[128K, 256K)           6 |                                                    |

@us[xfs_file_open]:
[1]                 1819 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2, 4)               272 |@@@@@@@                                             |
[4, 8)                 0 |                                                    |
[8, 16)                9 |                                                    |
[16, 32)               7 |                                                    |

This output shows a bi-modal distribution for read latency, with a faster
mode of 724 reads that took between 0 and 1 microseconds, and a slower
mode of over 485 reads that took between 256 and 512 microseconds. It's
likely that the faster mode was a hit from the in-memory file system cache,
and the slower mode is a read from a storage device (disk).

This "latency" is measured from when the operation was issued from the VFS
interface to the file system, to when it completed. This spans everything:
block device I/O (disk I/O), file system CPU cycles, file system locks, run
queue latency, etc. This is a better measure of the latency suffered by
applications reading from the file system than measuring this down at the
block device interface.

Note that this only traces the common file system operations previously
listed: other file system operations (eg, inode operations including
getattr()) are not traced.


There is another version of this tool in bcc: https://github.com/iovisor/bcc
The bcc version provides command line options to customize the output.`
