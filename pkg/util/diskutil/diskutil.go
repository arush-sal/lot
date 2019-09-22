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
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/arush-sal/lot/pkg/util"
	"github.com/shirou/gopsutil/disk"
)

// DiskStat represents a physical disk and it's respective info
type DiskStat struct {
	Device            string
	Mountpoint        string
	Fstype            string
	Total             uint64
	Free              uint64
	Used              uint64
	UsedPercent       float64
	InodesTotal       uint64
	InodesUsed        uint64
	InodesFree        uint64
	InodesUsedPercent float64
}

// GetUsageStat returns slice of DiskStat with the usage info
func (dstat *DiskStat) GetUsageStat() error {
	ustat, err := disk.Usage(dstat.Mountpoint)
	util.ErrorCheck(err)

	// The disk package doesn't round of properly
	// therefore the final size is < 1 than the size reported by df -h
	// need to reimplement this.
	dstat.Total = ustat.Total
	dstat.Free = ustat.Free
	dstat.Used = ustat.Used
	dstat.UsedPercent = ustat.UsedPercent
	dstat.InodesTotal = ustat.InodesTotal
	dstat.InodesUsed = ustat.InodesUsed
	dstat.InodesFree = ustat.InodesFree
	dstat.InodesUsedPercent = ustat.InodesUsedPercent

	return err
}

// GetPartitions returns slice of DiskStat with the partition info
func GetPartitions() ([]*DiskStat, error) {
	var ds = []*DiskStat{}
	// False because we don't really care about non-physical disk partitions
	pstats, err := disk.Partitions(false)
	util.ErrorCheck(err)

	for _, pstat := range pstats {
		var d = &DiskStat{}
		d.Device = pstat.Device
		d.Mountpoint = pstat.Mountpoint
		d.Fstype = pstat.Fstype
		ds = append(ds, d)
	}
	return ds, err
}

// GetDiskStats returns slice of DiskStat with the partition and usage info
func GetDiskStats() ([]*DiskStat, error) {
	dstats, err := GetPartitions()

	for _, dstat := range dstats {
		err = dstat.GetUsageStat()
	}
	return dstats, err
}

// PrintUsageStats prints the DiskStat usage stats
func PrintUsageStats() error {
	const psformat = "%s\t|%s\t|%s\t|%.1f\t|%s\t|%s\t|%s\t|%.1f\t|%d\t|%d\t|%d\t|\n"
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	dsks, err := GetDiskStats()
	if err != nil {
		return err
	}

	fmt.Fprintf(tw, format, "Device", "Mount Path", "FS", "FREE%", "FREE", "USED", "TOTAL", "IFREE%", "IFREE", "IUSED", "ITOTAL")
	fmt.Fprintf(tw, format, "------", "----------", "--", "-----", "----", "-----", "-----", "------", "-----", "------", "------")
	for _, dsk := range dsks {

		util.ErrorCheck(dsk.GetUsageStat())
		free := util.TransformSize(dsk.Free)
		used := util.TransformSize(dsk.Used)
		total := util.TransformSize(dsk.Total)
		fmt.Fprintf(tw, psformat, dsk.Device, dsk.Mountpoint, dsk.Fstype, 100.0-dsk.UsedPercent, free, used, total, 100.0-dsk.InodesUsedPercent, dsk.InodesFree, dsk.InodesUsed, dsk.InodesTotal)
	}
	tw.Flush()

	return nil
}
