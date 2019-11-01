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

// BPFSnippet contains a bpftrace snippet along with its short description and example
type BPFSnippet struct {
	Desc    string
	Snippet string
	Example string
}

var snippetmap = map[string]*BPFSnippet{
	"bashreadline":   &BPFSnippet{bashreadlineDesc, bashreadline, bashreadlineExample},
	"biolatency":     &BPFSnippet{biolatencyDesc, biolatency, biolatencyExample},
	"biosnoop":       &BPFSnippet{biosnoopDesc, biosnoop, biosnoopExample},
	"biostacks":      &BPFSnippet{biostacksDesc, biostacks, biostacksExample},
	"bitesize":       &BPFSnippet{bitesizeDesc, bitesize, bitesizeExample},
	"capable":        &BPFSnippet{capableDesc, capable, capableExample},
	"cpuwalk":        &BPFSnippet{cpuwalkDesc, cpuwalk, cpuwalkExample},
	"dcsnoop":        &BPFSnippet{dcsnoopDesc, dcsnoop, dcsnoopExample},
	"execsnoop":      &BPFSnippet{execsnoopDesc, execsnoop, execsnoopExample},
	"gethostlatency": &BPFSnippet{gethostlatencyDesc, gethostlatency, gethostlatencyExample},
	"killsnoop":      &BPFSnippet{killsnoopDesc, killsnoop, killsnoopExample},
	"loads":          &BPFSnippet{loadsDesc, loads, loadsExample},
	"mdflush":        &BPFSnippet{mdflushDesc, mdflush, mdflushExample},
	"naptime":        &BPFSnippet{naptimeDesc, naptime, naptimeExample},
	"oomkill":        &BPFSnippet{oomkillDesc, oomkill, oomkillExample},
	"opensnoop":      &BPFSnippet{opensnoopDesc, opensnoop, opensnoopExample},
	"pidpersec":      &BPFSnippet{pidpersecDesc, pidpersec, pidpersecExample},
	"runqlat":        &BPFSnippet{runqlatDesc, runqlat, runqlatExample},
	"runqlen":        &BPFSnippet{runqlenDesc, runqlen, runqlenExample},
	"setuids":        &BPFSnippet{setuidsDesc, setuids, setuidsExample},
	"statsnoop":      &BPFSnippet{statsnoopDesc, statsnoop, statsnoopExample},
	"swapin":         &BPFSnippet{swapinDesc, swapin, swapinExample},
	"syncsnoop":      &BPFSnippet{syncsnoopDesc, syncsnoop, syncsnoopExample},
	"syscount":       &BPFSnippet{syscountDesc, syscount, syscountExample},
	"tcpaccept":      &BPFSnippet{tcpacceptDesc, tcpaccept, tcpacceptExample},
	"tcpconnect":     &BPFSnippet{tcpconnectDesc, tcpconnect, tcpconnectExample},
	"tcpdrop":        &BPFSnippet{tcpdropDesc, tcpdrop, tcpdropExample},
	"tcplife":        &BPFSnippet{tcplifeDesc, tcplife, tcplifeExample},
	"tcpretrans":     &BPFSnippet{tcpretransDesc, tcpretrans, tcpretransExample},
	"tcpsynbl":       &BPFSnippet{tcpsynblDesc, tcpsynbl, tcpsynblExample},
	"threadsnoop":    &BPFSnippet{threadsnoopDesc, threadsnoop, threadsnoopExample},
	"vfscount":       &BPFSnippet{vfscountDesc, vfscount, vfscountExample},
	"vfsstat":        &BPFSnippet{vfsstatDesc, vfsstat, vfsstatExample},
	"writeback":      &BPFSnippet{writebackDesc, writeback, writebackExample},
	"xfsdist":        &BPFSnippet{xfsdistDesc, xfsdist, xfsdistExample},
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

// ExecuteSnippet executes the provided bpftrace snippet
func ExecuteSnippet(arg string) {
	var cmd *exec.Cmd
	btpath, err := exec.LookPath("bpftrace")
	util.ErrorCheck(err)
	file := createSnippetFile(arg)

	cmd = util.GetSudoOrDie()
	cmd.Args = append(cmd.Args, btpath, file.Name())

	util.ErrorCheck(cmd.Run())
}

// ExplainSnippet prints the example and long description of the provided bpftrace snippet
func ExplainSnippet(arg string) {
	fmt.Println(snippetmap[arg].Example)
}
