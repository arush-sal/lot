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

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/infracloudio/lot/pkg/util"
)

// BPFSnippet represents a bpftrace snippet
type BPFSnippet struct {
	Desc    string
	Snippet string
	Example string
}

var snippetmap = map[string]*BPFSnippet{
	"bashreadline":   &BPFSnippet{bashreadlineDesc, bashreadline, bashreadline_example},
	"biolatency":     &BPFSnippet{biolatencyDesc, biolatency, biolatency_example},
	"biosnoop":       &BPFSnippet{biosnoopDesc, biosnoop, biosnoop_example},
	"biostacks":      &BPFSnippet{biostacksDesc, biostacks, biostacks_example},
	"bitesize":       &BPFSnippet{bitesizeDesc, bitesize, bitesize_example},
	"capable":        &BPFSnippet{capableDesc, capable, capable_example},
	"cpuwalk":        &BPFSnippet{cpuwalkDesc, cpuwalk, cpuwalk_example},
	"dcsnoop":        &BPFSnippet{dcsnoopDesc, dcsnoop, dcsnoop_example},
	"execsnoop":      &BPFSnippet{execsnoopDesc, execsnoop, execsnoop_example},
	"gethostlatency": &BPFSnippet{gethostlatencyDesc, gethostlatency, gethostlatency_example},
	"killsnoop":      &BPFSnippet{killsnoopDesc, killsnoop, killsnoop_example},
	"loads":          &BPFSnippet{loadsDesc, loads, loads_example},
	"mdflush":        &BPFSnippet{mdflushDesc, mdflush, mdflush_example},
	"naptime":        &BPFSnippet{naptimeDesc, naptime, naptime_example},
	"oomkill":        &BPFSnippet{oomkillDesc, oomkill, oomkill_example},
	"opensnoop":      &BPFSnippet{opensnoopDesc, opensnoop, opensnoop_example},
	"pidpersec":      &BPFSnippet{pidpersecDesc, pidpersec, pidpersec_example},
	"runqlat":        &BPFSnippet{runqlatDesc, runqlat, runqlat_example},
	"runqlen":        &BPFSnippet{runqlenDesc, runqlen, runqlen_example},
	"setuids":        &BPFSnippet{setuidsDesc, setuids, setuids_example},
	"statsnoop":      &BPFSnippet{statsnoopDesc, statsnoop, statsnoop_example},
	"swapin":         &BPFSnippet{swapinDesc, swapin, swapin_example},
	"syncsnoop":      &BPFSnippet{syncsnoopDesc, syncsnoop, syncsnoop_example},
	"syscount":       &BPFSnippet{syscountDesc, syscount, syscount_example},
	"tcpaccept":      &BPFSnippet{tcpacceptDesc, tcpaccept, tcpaccept_example},
	"tcpconnect":     &BPFSnippet{tcpconnectDesc, tcpconnect, tcpconnect_example},
	"tcpdrop":        &BPFSnippet{tcpdropDesc, tcpdrop, tcpdrop_example},
	"tcplife":        &BPFSnippet{tcplifeDesc, tcplife, tcplife_example},
	"tcpretrans":     &BPFSnippet{tcpretransDesc, tcpretrans, tcpretrans_example},
	"tcpsynbl":       &BPFSnippet{tcpsynblDesc, tcpsynbl, tcpsynbl_example},
	"threadsnoop":    &BPFSnippet{threadsnoopDesc, threadsnoop, threadsnoop_example},
	"vfscount":       &BPFSnippet{vfscountDesc, vfscount, vfscount_example},
	"vfsstat":        &BPFSnippet{vfsstatDesc, vfsstat, vfsstat_example},
	"writeback":      &BPFSnippet{writebackDesc, writeback, writeback_example},
	"xfsdist":        &BPFSnippet{xfsdistDesc, xfsdist, xfsdist_example},
}

// IsValidSnippet validates wheter a given snippetname is valid or not
func IsValidSnippet(arg string) bool {
	if _, ok := snippetmap[arg]; !ok {
		return false
	}
	return true
}

// ListSnippets prints the list of available snippets
func ListSnippets() {
	const sformat = "%v\t|%v\t\n"
	const hformat = "%v\t%v\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 1, ' ', 0)
	fmt.Fprintf(tw, hformat, "NAME", "DESCRIPTION")
	fmt.Fprintf(tw, hformat, "----", "-----------")
	for name, snippet := range snippetmap {
		fmt.Fprintf(tw, sformat, name, snippet.Desc)
	}
	tw.Flush()
}

func checkKernelVersion() (major bool, minor bool) {
	major, minor = true, true

	cmd := exec.Command("uname", "-r")
	var out bytes.Buffer
	cmd.Stdout = &out
	util.ErrorCheck(cmd.Run())
	kver := strings.Split(out.String(), ".")
	majorVersion, err := strconv.ParseInt(kver[0], 10, 32)
	minorVersion, err := strconv.ParseInt(kver[1], 10, 32)

	util.ErrorCheck(err)
	if majorVersion < 4 {
		major = false
	}
	if minorVersion < 9 {
		minor = false
	}
	return
}

func getSnippet(arg string) (string, error) {
	if !IsValidSnippet(arg) {
		return "", os.ErrNotExist
	}

	v, _ := snippetmap[arg]

	return v.Snippet, nil

}

func createSnippetFile(arg string) *os.File {
	tmpFile, err := ioutil.TempFile("", arg+"*.bt")
	util.ErrorCheck(err)
	snippet, err := getSnippet(arg)
	util.ErrorCheck(err)
	_, err = tmpFile.WriteString(snippet)
	util.ErrorCheck(err)
	return tmpFile
}

func ExecuteSnippet(arg string) {
	var cmd *exec.Cmd
	btpath, err := exec.LookPath("bpftrace")
	util.ErrorCheck(err)
	file := createSnippetFile(arg)

	cmd = util.GetSudoOrDie()
	cmd.Args = append(cmd.Args, btpath, file.Name())

	util.ErrorCheck(cmd.Run())
}
