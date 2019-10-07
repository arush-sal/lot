// +build linux

package dashboard

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/arush-sal/lot/pkg/util"
	"github.com/arush-sal/lot/pkg/util/procutil"
	"github.com/arush-sal/lot/pkg/util/sysutil"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

// ProcessDashboard creates a dashboard for processes
func ProcessDashboard() {
	err := ui.Init()
	if err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()
	ps, err := procutil.GetProcessStats()
	util.ErrorCheck(err)
	rgauge := ramGauge(ramInfo())
	rlist := pramList(ps)
	cgauge := cpuGauge(cpuPercentage())
	clist := pcpuList(ps)
	tlist := treeList()
	sList := []*widgets.List{rlist, clist}
	ui.Render(rgauge, rlist, cgauge, clist, tlist)
	previousKey := ""
	selectedList := sList[0]
	uiEvents := ui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		case "j", "<Down>":
			selectedList.ScrollDown()
		case "k", "<Up>":
			selectedList.ScrollUp()
		case "<C-d>":
			selectedList.ScrollHalfPageDown()
		case "<C-u>":
			selectedList.ScrollHalfPageUp()
		case "<C-f>":
			selectedList.ScrollPageDown()
		case "<C-b>":
			selectedList.ScrollPageUp()
		case "g":
			if previousKey == "g" {
				selectedList.ScrollTop()
			}
		case "<Home>":
			selectedList.ScrollTop()
		case "G", "<End>":
			selectedList.ScrollBottom()
		case "<Tab>":
			idx := cycleListNumb(sList, selectedList)
			selectedList = sList[idx]
		}
		if previousKey == "g" {
			previousKey = ""
		} else {
			previousKey = e.ID
		}
		ui.Render(selectedList)
	}
}
func ramGauge(usedRAM float64, availRAM string) *widgets.Gauge {
	rg := widgets.NewGauge()
	rg.Title = "RAM Usage"
	rg.SetRect(0, 0, 90, 5)
	rg.Percent = int(usedRAM)
	rg.Label = fmt.Sprintf("%.1f%% Used (%s Available)", usedRAM, availRAM)
	rg.BarColor = ui.ColorRed
	rg.LabelStyle = ui.NewStyle(ui.ColorYellow)
	return rg
}
func cpuGauge(cpup float64) *widgets.Gauge {
	cg := widgets.NewGauge()
	cg.Title = "CPU Usage"
	cg.SetRect(0, 21, 90, 26)
	cg.Percent = int(cpup)
	cg.Label = fmt.Sprintf("%.1f%% Used", cpup)
	cg.BarColor = ui.ColorRed
	cg.LabelStyle = ui.NewStyle(ui.ColorYellow)
	return cg
}
func pramList(ps []*procutil.Process) *widgets.List {
	l := widgets.NewList()
	l.Title = "Top RAM consuming Processes"
	err := procutil.Top(ps, "ram")
	util.ErrorCheck(err)
	for i := 0; i < 15; i++ {
		if ps[i].IsGhostProcess() {
			continue
		}
		val := "[" + strconv.Itoa(i+1) + "]" + strings.Trim(ps[i].Name, "()") + "(" + strconv.Itoa(ps[i].Pid) + ")" + " : " + strconv.FormatFloat(float64(ps[i].Memp), 'f', 3, 32)
		l.Rows = append(l.Rows, val)
	}
	l.TextStyle = ui.NewStyle(ui.ColorGreen)
	l.WrapText = false
	l.SetRect(0, 5, 90, 21)
	return l
}
func pcpuList(ps []*procutil.Process) *widgets.List {
	l := widgets.NewList()
	l.Title = "Top CPU consuming Processes"
	err := procutil.Top(ps, "cpu")
	util.ErrorCheck(err)
	for i := 0; i < 20; i++ {
		if ps[i].IsGhostProcess() {
			continue
		}
		val := "[" + strconv.Itoa(i+1) + "]" + strings.Trim(ps[i].Name, "()") + "(" + strconv.Itoa(ps[i].Pid) + ")" + " : " + strconv.FormatFloat(float64(ps[i].Memp), 'f', 3, 32)
		l.Rows = append(l.Rows, val)
	}
	l.TextStyle = ui.NewStyle(ui.ColorGreen)
	l.WrapText = false
	l.SetRect(0, 26, 90, 45)
	return l
}
func treeList() *widgets.Paragraph {
	l := widgets.NewParagraph()
	l.Title = "CPU List"
	l.Text = procutil.GetProcessTree().Print()
	l.TextStyle = ui.NewStyle(ui.ColorGreen)
	l.WrapText = false
	l.SetRect(90, 0, 190, 45)
	return l
}
func cycleListNumb(sList []*widgets.List, currList *widgets.List) int {
	var idx int
	for i, list := range sList {
		if list == currList {
			idx = i
			break
		}
	}
	if idx == len(sList)-1 {
		idx = 0
	} else {
		idx += 1
	}
	return idx
}

func ramInfo() (float64, string) {
	ram, err := mem.VirtualMemory()
	util.ErrorCheck(err)
	return ram.UsedPercent, util.TransformSize(ram.Available)
}

func cpuPercentage() float64 {
	cput, err := cpu.Times(false)
	util.ErrorCheck(err)
	fmt.Printf("%#v\n", cput[0].Total())
	info, err := sysutil.GetSysInfo()
	util.ErrorCheck(err)
	tp := (cput[0].Total() / float64(info.Uptime)) * 100
	cores, err := cpu.Counts(true)
	util.ErrorCheck(err)
	return tp / float64(cores)
}
