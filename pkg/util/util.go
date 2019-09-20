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
	"os"
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
func TransformSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + "B"
	case n < 1048576 && n > 1024:
		n = n / 1024
		return strconv.FormatInt(n, 10) + "kB"
	default:
		n = (n / 1024) / 1024
		return strconv.FormatInt(n, 10) + "mB"
	}
}

func AtoI64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	ErrorCheck(err)
	return n
}

func AtoI(s string) int {
	n, err := strconv.Atoi(s)
	ErrorCheck(err)
	return n
}
