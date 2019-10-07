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
	"fmt"
	"sort"
	"strconv"

	"github.com/arush-sal/lot/pkg/util"
	"github.com/disiqueira/gotree"
)

type process struct {
	Name string
	Pid  string
}

// GetProcessTree returns a tree with process ancestral hierarchy
func GetProcessTree() gotree.Tree {
	list := make(map[int][]*process)
	processes, err := GetProcessStats()
	util.ErrorCheck(err)

	for _, ps := range processes {
		if ps.IsGhostProcess() {
			continue
		}
		p := new(process)
		p.Name = ps.Name
		p.Pid = strconv.Itoa(ps.Pid)
		list[ps.Ppid] = append(list[ps.Ppid], p)
	}

	ppids := []int{}

	for key := range list {
		ppids = append(ppids, key)
	}

	sort.Ints(ppids)
	var gparent = gotree.New("0")
	for _, ppid := range ppids {
		if ppid == 0 {
			continue
		}
		parent := gotree.New(strconv.FormatInt(int64(ppid), 10))

		for _, ps := range list[ppid] {
			processInfo := ps.Name + "(" + ps.Pid + ")"
			parent.Add(processInfo)
		}
		gparent.AddTree(parent)
	}
	return gparent
}

// PrintProcessTree prints a tree of processes with their ancestral hierarchy
func PrintProcessTree() {
	fmt.Println(GetProcessTree().Print())
}
