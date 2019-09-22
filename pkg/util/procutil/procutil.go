/*
	Copyright © 2019 LoT Authors

	Licensed under the Apache License, Version 2.0 (the "License");,
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package procutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arush-sal/lot/pkg/util"
	"github.com/arush-sal/lot/pkg/util/sysutil"
	gopsutil "github.com/shirou/gopsutil/process"

	"golang.org/x/sys/unix"
)

// Process represents a process
type Process struct {
	/*(1) */ Pid int
	/*(2) */ Name string
	/*(2) */ Ppid int
	Stat          Stat
	User          string
	Cmdline       string
	Cput          float64
	Cpup          float64
	Memp          float32
}

// Stat represents all of the info found about a process
type Stat struct {
	/*(3) */ State string
	/*(5) */ Pgrp int
	/*(6) */ Session int
	/*(7) */ TtyNr int
	/*(8) */ Tpgid int
	/*(9) */ Flags uint
	/*(10) */ Minflt int
	/*(11) */ Cminflt int
	/*(12) */ Majflt int
	/*(13) */ Cmajflt int
	/*(14) */ Utime int
	/*(15) */ Stime int
	/*(16) */ Cutime int64
	/*(17) */ Cstime int64
	/*(18) */ Priority int64
	/*(19) */ Nice int64
	/*(20) */ NumThreads int64
	/*(21) */ Itrealvalue int64
	/*(22) */ Starttime int64
	/*(23) */ Vsize int
	/*(24) */ Rss int64
	/*(25) */ Rsslim uint64
	/*(31) */ Signal int
	/*(32) */ Blocked int
	/*(33) */ Sigignore int
	/*(34) */ Sigcatch int
	/*(36) */ Nswap int
	/*(37) */ Cnswap int
	/*(38) */ ExitSignal int
	/*(39) */ Processor int
	/*(40) */ RtPriority uint
	/*(41) */ Policy uint
	/*(42) */ DelayacctBlkioTicks uint64
	/*(43) */ GuestTime int
	/*(44) */ CguestTime int64
	/*(45) */ StartData int
	/*(46) */ EndData int
	/*(47) */ StartBrk int
	/*(48) */ ArgStart int
	/*(49) */ ArgEnd int
	/*(50) */ EnvStart int
	/*(51) */ EnvEnd int
	/*(52) */ ExitCode int
}

var systemClockTick = sysutil.GetClockTick()

// GetStat will return the stats for a given process
func (p *Process) GetStat() (err error) {
	var cl, sstat string
	var nameStart, nameEnd int

	stats, err := os.Open(util.CreateProcPath(util.ProcLocation, strconv.Itoa(p.Pid), "stat"))
	if err != nil {
		return err
	}
	defer stats.Close()

	scanner := bufio.NewScanner(stats)
	for scanner.Scan() {
		sstat = scanner.Text()
		nameStart = strings.IndexRune(sstat, '(')
		nameEnd = strings.IndexRune(sstat[nameStart:], ')')
	}

	s := &Stat{}
	_, err = fmt.Sscanf(strings.TrimSpace(sstat[nameStart+nameEnd+2:]), "%s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d", &s.State, &p.Ppid, &s.Pgrp, &s.Session, &s.TtyNr, &s.Tpgid, &s.Flags, &s.Minflt, &s.Cminflt, &s.Majflt, &s.Cmajflt, &s.Utime, &s.Stime, &s.Cutime, &s.Cstime, &s.Priority, &s.Nice, &s.NumThreads, &s.Itrealvalue, &s.Starttime, &s.Vsize, &s.Rss, &s.Rsslim, &s.Signal, &s.Blocked, &s.Sigignore, &s.Sigcatch, &s.Nswap, &s.Cnswap, &s.ExitSignal, &s.Processor, &s.RtPriority, &s.Policy, &s.DelayacctBlkioTicks, &s.GuestTime, &s.CguestTime, &s.StartData, &s.EndData, &s.StartBrk, &s.ArgStart, &s.ArgEnd, &s.EnvStart, &s.EnvEnd, &s.ExitCode)
	if err != nil {
		return err
	}

	cmdline, err := os.Open(util.CreateProcPath(util.ProcLocation, strconv.Itoa(p.Pid), "cmdline"))
	if err != nil {
		return err
	}
	defer cmdline.Close()

	cmdScanner := bufio.NewScanner(cmdline)
	for cmdScanner.Scan() {
		cl = cmdScanner.Text()
	}

	p.Name = sstat[nameStart : nameStart+nameEnd+1]
	p.Cmdline = cl
	p.Stat = *s

	return nil
}

// GetPids returns a slice of IDs for all of the currently running processes
func GetPids() (pids []string, err error) {
	p, err := os.Open(util.ProcLocation)
	if err != nil {
		return nil, err
	}
	defer p.Close()

	pids = make([]string, 0)
	for {
		fileInfos, err := p.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		for _, fileInfo := range fileInfos {
			// We only care about directories, since all pids are dirs
			if !fileInfo.IsDir() {
				continue
			}

			// We only care if the name starts with a numeric
			name := fileInfo.Name()
			if pid, err := strconv.Atoi(name); err == nil {
				spid := strconv.Itoa(pid)
				pids = append(pids, spid)
			}
		}
	}
	return pids, err
}

// GetProcessStats returns a list of processes with their respective info
func GetProcessStats() ([]*Process, error) {
	pids, err := GetPids()
	var p = make([]*Process, len(pids))
	if err != nil {
		return nil, err
	}
	for idx, spid := range pids {
		pid, err := strconv.Atoi(spid)
		if err != nil {
			return nil, err
		}
		ps := &Process{Pid: pid}
		err = ps.GetStat()
		if err == err.(*os.PathError) {
			ps.Name = "Ghost Process"
			p[idx] = ps
			continue
		}
		util.ErrorCheck(err)

		util.ErrorCheck(ps.GetStatus())
		util.ErrorCheck(ps.ExternalStats())

		p[idx] = ps
	}
	return p, nil
}

// ListProcess will list all the process in a tabular form
func ListProcess() error {
	const psformat = "%v\t|%v\t|%.3f\t|%.3f\t|%v\t|%v\t|%v\t|%v\t|%v\t|%.3f\t|%v\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	ps, err := GetProcessStats()
	if err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")
	fmt.Fprintf(tw, format, "----", "---", "----", "----", "---", "---", "---", "----", "-----", "----", "-------")
	for _, p := range ps {
		if p.IsGhostProcess() {
			continue
		}

		stat := p.Stat
		processStartTime := startTime(stat.createTime())

		fmt.Fprintf(tw, psformat, p.User, p.Pid, p.Cpup, p.Memp, util.TransformSize(uint64(stat.Vsize)), util.TransformSize(uint64(stat.Rss)), p.getTerminalName(), stat.State, processStartTime, p.Cput, strings.Trim(p.Name, "()"))
	}
	tw.Flush()

	return nil
}

func (s *Stat) createTime() int64 {
	systemClockTick := sysutil.GetClockTick()

	now := time.Now().Unix()
	info, err := sysutil.GetSysInfo()
	util.ErrorCheck(err)
	bootTime := now - info.Uptime
	return ((s.Starttime / systemClockTick) + bootTime)
}

func startTime(t int64) string {
	sts := time.Unix(t, 0)
	dur := time.Since(sts)
	ts := int(dur.Hours())

	if ts > 23 {
		return sts.Format("Mon 2")
	}

	return sts.Format("15:04")
}

// GetUserName returns info about the real user of a process
func (p *Process) GetUserName(s string) (err error) {
	sl := strings.Split(s, "\t")
	usr, err := user.LookupId(sl[1])
	if err != nil {
		return err
	}
	p.User = usr.Username
	return nil
}

// GetVMRss returns the virtual memory resident set size of a process
func (p *Process) GetVMRss(s string) (err error) {
	sl := strings.Split(s, "\t")
	vmRss := strings.Split(strings.Trim(sl[1], " "), " ")
	rss, err := strconv.ParseInt(vmRss[0], 0, 64)
	p.Stat.Rss = rss * 1024
	return
}

// GetStatus parses the status file of a process
// and gets the process's UID and VmRSS
func (p *Process) GetStatus() (err error) {
	statusf, err := os.Open(util.CreateProcPath(util.ProcLocation, strconv.Itoa(p.Pid), "status"))
	defer statusf.Close()

	scanner := bufio.NewScanner(statusf)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, "Uid") {
			if err := p.GetUserName(s); err != nil {
				return err
			}
		}
		if strings.HasPrefix(s, "VmRSS") {
			if err := p.GetVMRss(s); err != nil {
				return err
			}
		}
	}
	return
}

func (p *Process) getTerminalName() (terminal string) {
	t := uint64(p.Stat.TtyNr)
	major := unix.Major(t)
	minor := unix.Minor(t)
	switch major {
	case 4:
		terminal = "tty"
	case 136:
		terminal = "pts/"
	default:
		return ""
	}
	return terminal + strconv.FormatUint(uint64(minor), 10)
}

func (p *Process) IsGhostProcess() bool {
	if p.Name == "Ghost Process" {
		return true
	}
	return false
}

// ExternalStats get stats from the gopsutil
func (p *Process) ExternalStats() error {
	proc := gopsutil.Process{
		Pid: int32(p.Pid),
	}
	cpup, err := proc.CPUPercent()
	p.Cpup = cpup
	if err != nil {
		return err
	}

	t, err := proc.Times()
	if err != nil {
		return err
	}
	p.Cput = t.Total()

	p.Memp, err = proc.MemoryPercent()
	return err
}
