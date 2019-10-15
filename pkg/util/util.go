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

package util

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"strconv"
)

const (
	// ProcLocation is the default location for the proc folder
	ProcLocation = "/proc"
)

// ErrorCheck will print and exit if the error passed is not empty
func ErrorCheck(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// CreateProcPath returns a proc location build from the arguments passed
func CreateProcPath(args ...string) string {
	var procPath string
	for _, str := range args {
		procPath = procPath + "/" + str
	}
	return procPath
}

// TransformSize takes bytes in int64 format and returns it in a human readable format
func TransformSize(n uint64) string {
	switch {
	case n < 1024:
		return strconv.FormatUint(n, 10) + "B"
	case n < 1048576 && n > 1024:
		tmp := float64(n) / 1024
		return strconv.FormatUint(uint64(math.Round(tmp)), 10) + "KiB"
	case n < 1073741824:
		tmp := float64(n) / 1048576
		return strconv.FormatUint(uint64(math.Round(tmp)), 10) + "MiB"
	default:
		tmp := float64(n) / 1073741824
		return strconv.FormatUint(uint64(math.Round(tmp)), 10) + "GiB"
	}
}

func IsRoot() bool {
	usr, err := user.Current()
	ErrorCheck(err)
	if usr.Uid != "0" {
		if !checkSudoSession() {
			return false
		}
	}
	return true
}

func checkSudoSession() bool {
	cmd := exec.Command("sudo", "-n", "true")
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func getCurrentShell() string {
	return os.Getenv("SHELL")
}

func GetSudoOrDie() *exec.Cmd {

	if !IsRoot() {
		fmt.Println("Needs root privileges to run")
	}
	cmd := exec.Command("sudo")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}
