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

package sysutil

import (
	"encoding/binary"
	"io/ioutil"
	"syscall"

	"github.com/arush-sal/lot/pkg/util"
)

const (
	// ATClockTick Frequency of times()
	ATClockTick = 17
	// SysClockTick Common system clock tick
	SysClockTick      = 100
	uintSize     uint = 32 << (^uint(0) >> 63)
)

// System represents informations about a system
type System struct {
	BootTime string
}

// GetSysInfo create, populate and return a Sysinfo_t struct
func GetSysInfo() (info *syscall.Sysinfo_t, err error) {
	info = &syscall.Sysinfo_t{}
	err = syscall.Sysinfo(info)
	return
}

// GetClockTick will return a system's clock ticks per second
func GetClockTick() int64 {
	auxv, err := ioutil.ReadFile(util.CreateProcPath(util.ProcLocation, "self/auxv"))
	if err == nil {
		pb := int(uintSize / 8)
		for i := 0; i < len(auxv)-pb*2; i += pb * 2 {
			var tag, val uint
			switch uintSize {
			case 32:
				tag = uint(binary.LittleEndian.Uint32(auxv[i:]))
				val = uint(binary.LittleEndian.Uint32(auxv[i+pb:]))
			case 64:
				tag = uint(binary.LittleEndian.Uint64(auxv[i:]))
				val = uint(binary.LittleEndian.Uint64(auxv[i+pb:]))
			}

			switch tag {
			case ATClockTick:
				return int64(val)
			}
		}
	}
	return SysClockTick
}
