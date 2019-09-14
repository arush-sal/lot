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
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/shirou/gopsutil/process"

	"github.com/arush-sal/lot/pkg/util"
	"github.com/arush-sal/lot/pkg/util/sysutil"
)

// Process represents a process
type Process struct {
	Name    string
	Pid     int
	Ppid    int
	Stat    Stat
	User    string
	Cmdline string
}

// Stat represents all of the info found about a process
type Stat struct {
	/*(2) */ Comm string
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
func (p *Process) GetStat(pid string) (err error) {
	var info []int
	var name, stateFound, cl string
	var rsslim uint64

	stats, err := os.Open(util.CreateProcPath(util.ProcLocation, pid, "stat"))
	if err != nil {
		return err
	}
	defer stats.Close()

	scanner := bufio.NewScanner(stats)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		sstat := scanner.Text()
		stat, err := strconv.Atoi(sstat)
		if err != nil && err.(*strconv.NumError).Err == strconv.ErrSyntax && len(sstat) > 1 {
			name = sstat
			stat = -97
		}

		if err != nil && err.(*strconv.NumError).Err == strconv.ErrSyntax && len(sstat) == 1 {
			stateFound = sstat
			stat = -98
		}

		if err != nil && err.(*strconv.NumError).Err == strconv.ErrRange {
			rsslim, err = strconv.ParseUint(sstat, 10, 64)
			stat = -99
		}
		info = append(info, stat)
	}

	cmdline, err := os.Open(util.CreateProcPath(util.ProcLocation, pid, "cmdline"))
	if err != nil {
		return err
	}
	defer cmdline.Close()

	cmdScanner := bufio.NewScanner(cmdline)
	for cmdScanner.Scan() {
		cl = cmdScanner.Text()
	}

	// id := strconv.Itoa(info[4])
	// usr, err := user.LookupId(id)
	// if err != nil {
	// 	return err
	// }

	p.Name = name
	p.Pid = info[0]
	p.Ppid = info[3]
	p.Cmdline = cl
	p.Stat = Stat{
		State:               stateFound,
		Pgrp:                info[4],
		Session:             info[5],
		TtyNr:               info[6],
		Tpgid:               info[7],
		Flags:               uint(info[8]),
		Minflt:              info[9],
		Cminflt:             info[10],
		Majflt:              info[11],
		Cmajflt:             info[12],
		Utime:               info[13],
		Stime:               info[14],
		Cutime:              int64(info[15]),
		Cstime:              int64(info[16]),
		Priority:            int64(info[17]),
		Nice:                int64(info[18]),
		NumThreads:          int64(info[19]),
		Itrealvalue:         int64(info[20]),
		Starttime:           int64(info[21]),
		Vsize:               info[22],
		Rss:                 int64(info[23]),
		Rsslim:              rsslim,
		Signal:              info[25],
		Blocked:             info[31],
		Sigignore:           info[32],
		Sigcatch:            info[33],
		Nswap:               info[34],
		Cnswap:              info[36],
		ExitSignal:          info[37],
		Processor:           info[38],
		RtPriority:          uint(info[39]),
		Policy:              uint(info[40]),
		DelayacctBlkioTicks: uint64(info[41]),
		GuestTime:           info[42],
		CguestTime:          int64(info[43]),
		StartData:           info[44],
		EndData:             info[45],
		StartBrk:            info[46],
		ArgStart:            info[47],
		ArgEnd:              info[48],
		EnvStart:            info[49],
		EnvEnd:              info[50],
		ExitCode:            info[51],
	}

	return nil
}

func getPids() (pids []string, err error) {
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
	pids, err := getPids()
	var p = make([]*Process, 0)
	if err != nil {
		return nil, err
	}
	for _, pid := range pids {
		ps := &Process{}
		err = ps.GetStat(pid)
		if err != nil {
			return nil, nil
		}
		p = append(p, ps)
	}
	return p, nil
}

// ListProcess will list all the process in a tabular form
func ListProcess() error {
	const psformat = "%v\t|%v\t|%.3f\t|%.3f\t|%v\t|%v\t|%v\t|%v\t|%v\t|%.3f\t|%v\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 2, ' ', 0)
	ps, err := GetProcessStats()
	if err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")
	fmt.Fprintf(tw, format, "----", "---", "----", "----", "---", "---", "---", "----", "-----", "----", "-------")
	for _, p := range ps {
		proc := process.Process{
			Pid: int32(p.Pid),
		}
		username, err := proc.Username()
		util.ErrorCheck(err)
		cpup, err := proc.CPUPercent()
		util.ErrorCheck(err)
		terminal, err := proc.Terminal()
		util.ErrorCheck(err)
		t, err := proc.Times()
		util.ErrorCheck(err)
		cput := t.Total()
		stat := p.Stat
		processStartTime := startTime(stat.createTime())
		memp, err := proc.MemoryPercent()
		util.ErrorCheck(err)

		fmt.Fprintf(tw, psformat, username, p.Pid, cpup, memp, transformSize(int64(stat.Vsize)), transformSize(stat.Rss), terminal, stat.State, processStartTime, cput, strings.Trim(p.Name, "()"))
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

func transformSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + "B"
	case n < 1048576 && n > 1024:
		n = n / 1024
		return strconv.FormatInt(n, 10) + "kB"
	default:
		n = (n / 1024) / 1024
		return strconv.FormatInt(n, 10) + "mB"
	}
}
