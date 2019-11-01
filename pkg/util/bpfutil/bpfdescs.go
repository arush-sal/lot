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
