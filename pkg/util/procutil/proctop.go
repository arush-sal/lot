// +build linux

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
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/infracloudio/lot/pkg/util"
)

type lessFunc func(p1, p2 *Process) bool

// multiSorter implements the Sort interface, sorting the changes within.
type multiSorter struct {
	usage []*Process
	less  []lessFunc
}

// Sort sorts the argument slice according to the less functions passed to OrderedBy.
func (ms *multiSorter) Sort(usage []*Process) {
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

// Top will return top result for RAM and CPU
func Top(ps []*Process, res string) error {
	pidFunc := func(c1, c2 *Process) bool {
		return c1.Pid < c2.Pid
	}
	cpuFunc := func(c1, c2 *Process) bool {
		return c1.Cpup > c2.Cpup
	}
	memFunc := func(c1, c2 *Process) bool {
		return c1.Memp > c2.Memp
	}
	switch res {
	case "cpu":
		OrderedBy(cpuFunc, pidFunc).Sort(ps)
	case "ram":
		OrderedBy(memFunc, pidFunc).Sort(ps)
	default:
		return errors.New("unknown resource type")
	}
	return nil
}

// MemTop will list all the process in a tabular form
func MemTop() error {
	const tformat = "%.3f\t|%v\t|%v\t|%.3f\t|%v\t|%.3f\t|%v\t|%v\t|%v\t|%v\t|%v\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	ps, err := GetProcessStats()
	if err != nil {
		return err
	}

	if err := Top(ps, "ram"); err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "%MEM", "RSS", "VSZ", "%CPU", "START", "TIME", "PID", "USER", "TTY", "STAT", "COMMAND")
	fmt.Fprintf(tw, format, "----", "---", "---", "----", "-----", "----", "---", "----", "---", "----", "-------")
	for _, p := range ps {
		if p.IsGhostProcess() {
			continue
		}

		stat := p.Stat
		processStartTime := startTime(stat.createTime())

		fmt.Fprintf(tw, tformat, p.Memp, util.TransformSize(uint64(stat.Rss)), util.TransformSize(uint64(stat.Vsize)), p.Cpup, processStartTime, p.Cput, p.Pid, p.User, p.getTerminalName(), stat.State, strings.Trim(p.Name, "()"))
	}
	tw.Flush()

	return nil
}

// CPUTop will list all the process in a tabular form
func CPUTop() error {
	const tformat = "%.3f\t|%.3f\t|%v\t|%.3f\t|%v\t|%v\t|%v\t|%v\t|%v\t|%v\t|%v\t\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	ps, err := GetProcessStats()
	if err != nil {
		return err
	}

	Top(ps, "cpu")

	fmt.Fprintf(tw, format, "%CPU", "TIME", "START", "%MEM", "VSZ", "RSS", "PID", "USER", "TTY", "STAT", "COMMAND")
	fmt.Fprintf(tw, format, "----", "-----", "----", "----", "---", "---", "---", "----", "---", "----", "-------")
	for _, p := range ps {
		if p.IsGhostProcess() {
			continue
		}

		stat := p.Stat
		processStartTime := startTime(stat.createTime())

		fmt.Fprintf(tw, tformat, p.Cpup, p.Cput, processStartTime, p.Memp, util.TransformSize(uint64(stat.Vsize)), util.TransformSize(uint64(stat.Rss)), p.Pid, p.User, p.getTerminalName(), stat.State, strings.Trim(p.Name, "()"))
	}
	tw.Flush()

	return nil
}
