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

package diskutil

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/infracloudio/lot/pkg/util"
	"github.com/infracloudio/lot/pkg/util/procutil"
)

// ProcessIOStat represents the IO stats of a process
type ProcessIOStat struct {
	Name         string
	Pid          int
	Readchar     int64
	Writechar    int64
	SyscallRead  int64
	SyscallWrite int64
	ReadBytes    int64
	WriteBytes   int64
}

type lessFunc func(p1, p2 *ProcessIOStat) bool

// multiSorter implements the Sort interface, sorting the changes within.
type multiSorter struct {
	usage []*ProcessIOStat
	less  []lessFunc
}

// Sort sorts the argument slice according to the less functions passed to OrderedBy.
func (ms *multiSorter) Sort(usage []*ProcessIOStat) {
	ms.usage = usage
	sort.Sort(ms)
}

// OrderedBy returns a Sorter that sorts using the less functions, in order.
// Call its Sort method to sort the data.
func OrderedBy(less ...lessFunc) *multiSorter {
	return &multiSorter{
		less: less,
	}
}

// Len is part of sort.Interface.
func (ms *multiSorter) Len() int {
	return len(ms.usage)
}

// Swap is part of sort.Interface.
func (ms *multiSorter) Swap(i, j int) {
	ms.usage[i], ms.usage[j] = ms.usage[j], ms.usage[i]
}

// Less is part of sort.Interface. It is implemented by looping along the
// less functions until it finds a comparison that discriminates between
// the two items (one is less than the other). Note that it can call the
// less functions twice per call. We could change the functions to return
// -1, 0, 1 and reduce the number of calls for greater efficiency: an
// exercise for the reader.
func (ms multiSorter) Less(i, j int) bool {
	p, q := ms.usage[i], ms.usage[j]
	// Try all but the last comparison.
	var k int
	for k = 0; k < len(ms.less)-1; k++ {
		less := ms.less[k]
		switch {
		case less(p, q):
			// p < q, so we have a decision.
			return true
		case less(q, p):
			// p > q, so we have a decision.
			return false
		}
		// p == q; try the next comparison.
	}
	// All comparisons to here said"equal", so just return whatever
	// the final comparison reports.
	return ms.less[k](p, q)
}

func (p *ProcessIOStat) getProcIOStat() (err error) {
	statusf, err := os.Open(util.CreateProcPath(util.ProcLocation, strconv.Itoa(p.Pid), "io"))
	defer statusf.Close()

	scanner := bufio.NewScanner(statusf)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, "rchar") {
			sl := strings.Split(s, " ")
			rchar, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.Readchar = rchar
		}
		if strings.HasPrefix(s, "wchar") {
			sl := strings.Split(s, " ")
			wchar, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.Writechar = wchar
		}
		if strings.HasPrefix(s, "syscr") {
			sl := strings.Split(s, " ")
			syscr, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.SyscallRead = syscr
		}
		if strings.HasPrefix(s, "syscw") {
			sl := strings.Split(s, " ")
			syscw, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.SyscallWrite = syscw
		}
		if strings.HasPrefix(s, "read_bytes") {
			sl := strings.Split(s, " ")
			rbytes, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.ReadBytes = rbytes
		}
		if strings.HasPrefix(s, "write_bytes") {
			sl := strings.Split(s, " ")
			wbytes, err := strconv.ParseInt(sl[1], 0, 64)
			if err != nil {
				return err
			}
			p.WriteBytes = wbytes
		}
	}
	return nil
}

func getProcIOStats() ([]*ProcessIOStat, error) {
	procs, err := procutil.GetProcessStats()
	if err != nil {
		return nil, err
	}
	var p = make([]*ProcessIOStat, len(procs))

	for idx, ps := range procs {
		pio := new(ProcessIOStat)
		if ps.IsGhostProcess() {
			pio.Name = "Ghost Process"
			p[idx] = pio
			continue
		}
		pio.Pid = ps.Pid
		pio.Name = ps.Name

		err = pio.getProcIOStat()
		p[idx] = pio
	}
	return p, nil
}

// Top will return top result for RAM and CPU
func Top(ps []*ProcessIOStat, res string) error {
	pidFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.Pid < c2.Pid
	}
	readCharFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.Readchar > c2.Readchar
	}
	readSyscallFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.SyscallRead > c2.SyscallRead
	}
	readByteFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.ReadBytes > c2.ReadBytes
	}
	writeCharFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.Writechar > c2.Writechar
	}
	writeSyscallFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.SyscallWrite > c2.SyscallWrite
	}
	writeByteFunc := func(c1, c2 *ProcessIOStat) bool {
		return c1.WriteBytes > c2.WriteBytes
	}
	switch res {
	case "read":
		OrderedBy(readByteFunc, readSyscallFunc, readCharFunc, pidFunc).Sort(ps)
	case "write":
		OrderedBy(writeByteFunc, writeSyscallFunc, writeCharFunc, pidFunc).Sort(ps)
	default:
		return errors.New("unknown resource type")
	}
	return nil
}

func ReadTop() error {
	const tformat = "%s\t|%d\t|%d\t|%d\t|%d\t|%d\t|%d\t|%d\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	ps, err := getProcIOStats()
	if err != nil {
		return err
	}
	if err := Top(ps, "read"); err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "NAME", "PID", "BYTES READ", "READ SYSCALLS", "CHARS READ", "BYTES WRITTEN", "WRITE SYSCALLS", "CHARS WRITTEN")
	fmt.Fprintf(tw, format, "----", "---", "----------", "-------------", "----------", "-------------", "--------------", "-------------")

	for _, p := range ps {
		if p.Name == "Ghost Process" {
			continue
		}

		var noio int8
		switch int64(0) {
		case p.ReadBytes:
			noio++
			fallthrough
		case p.SyscallRead:
			noio++
			fallthrough
		case p.Readchar:
			noio++
			fallthrough
		case p.WriteBytes:
			noio++
			fallthrough
		case p.SyscallWrite:
			noio++
			fallthrough
		case p.Writechar:
			noio++
		}

		if noio == 6 {
			continue
		}

		fmt.Fprintf(tw, tformat, strings.Trim(p.Name, "()"), p.Pid, p.ReadBytes, p.SyscallRead, p.Readchar, p.WriteBytes, p.SyscallWrite, p.Writechar)
	}
	tw.Flush()

	return nil
}

func WriteTop() error {
	const tformat = "%s\t|%d\t|%d\t|%d\t|%d\t|%d\t|%d\t|%d\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	ps, err := getProcIOStats()
	if err != nil {
		return err
	}
	if err := Top(ps, "write"); err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "NAME", "PID", "BYTES WRITTEN", "WRITE SYSCALLS", "CHARS WRITTEN", "BYTES READ", "READ SYSCALLS", "CHARS READ")
	fmt.Fprintf(tw, format, "----", "---", "-------------", "--------------", "-------------", "----------", "-------------", "----------")

	for _, p := range ps {
		if p.Name == "Ghost Process" {
			continue
		}

		var noio int8
		switch int64(0) {
		case p.ReadBytes:
			noio++
			fallthrough
		case p.SyscallRead:
			noio++
			fallthrough
		case p.Readchar:
			noio++
			fallthrough
		case p.WriteBytes:
			noio++
			fallthrough
		case p.SyscallWrite:
			noio++
			fallthrough
		case p.Writechar:
			noio++
		}

		if noio == 6 {
			continue
		}

		fmt.Fprintf(tw, tformat, strings.Trim(p.Name, "()"), p.Pid, p.WriteBytes, p.SyscallWrite, p.Writechar, p.ReadBytes, p.SyscallRead, p.Readchar)
	}
	tw.Flush()

	return nil
}
