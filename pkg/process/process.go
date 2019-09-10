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
package process

import (
	"bufio"
	"io"
	"os"
	"strconv"
)

// Info represents all of the info found about a process
type Info struct {
	/*(1) */ Pid int
	/*(2) */ Comm string
	/*(3) */ State string
	/*(4) */ Ppid int
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
	/*(22) */ Starttime uint64
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

// GetInfo will return a fully populated Info struct
func GetInfo(pid string) (processInfo *Info, err error) {
	var info []int
	var comm, stateFound string
	var rsslim uint64

	var state = map[string]string{
		"R": "Running",
		"S": "Sleeping in an interruptible wait",
		"D": "Waiting in uninterruptible disk sleep",
		"Z": "Zombie",
		"T": "Stopped (on a signal)",
		"t": "Tracing stop",
		"X": "Dead",
		"x": "Dead",
		"K": "Wakekill",
		"W": "Waking",
		"P": "Parked",
	}
	stats, err := os.Open("/proc/" + pid + "/stat")
	if err != nil {
		return nil, err
	}
	defer stats.Close()

	scanner := bufio.NewScanner(stats)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		sstat := scanner.Text()
		stat, err := strconv.Atoi(sstat)
		if err != nil && err.(*strconv.NumError).Err == strconv.ErrSyntax && len(sstat) > 1 {
			comm = sstat
			stat = -97
		}

		if err != nil && err.(*strconv.NumError).Err == strconv.ErrSyntax && len(sstat) == 1 {
			stateFound = state[sstat]
			stat = -98
		}

		if err != nil && err.(*strconv.NumError).Err == strconv.ErrRange {
			rsslim, err = strconv.ParseUint(sstat, 10, 64)
			stat = -99
		}
		info = append(info, stat)
	}

	return &Info{
		Pid:                 info[0],
		Comm:                comm,
		State:               stateFound,
		Ppid:                info[3],
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
		Starttime:           uint64(info[21]),
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
	}, nil
}

func getPids() (pids []string, err error) {
	p, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer p.Close()

	pids = make([]string, 0, 50)
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
				pids = append(pids, string(pid))
			}
		}
	}

	return pids, err
}

// GetProcesses returns a list of processes with their respective info
func GetProcesses() ([]*Info, error) {
	var processes []*Info
	pids, err := getPids()
	if err != nil {
		return nil, err
	}

	for _, pid := range pids {
		p, err := GetInfo(pid)
		// we don't want to break here, as the process might have died
		if err != nil {
			continue
		}
		processes = append(processes, p)
	}
	return processes, nil
}
