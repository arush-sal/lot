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
package cmd

import (
	"github.com/arush-sal/lot/pkg/util"
	"github.com/arush-sal/lot/pkg/util/diskutil"
	"github.com/spf13/cobra"
)

var read, write bool

// dtopCmd represents the dtop command
var dtopCmd = &cobra.Command{
	Use:   "top",
	Short: "Provides the sorted disk usage",
	Long: `lot disk top provides the sorted overview of the disk usage.
Sorting can be done by process or memory.`,
	Run: func(cmd *cobra.Command, args []string) {
		if (write && read) || (!write && !read) {
			util.ErrorCheck(diskutil.WriteTop())
		}
		if write {
			util.ErrorCheck(diskutil.WriteTop())
		}
		if read {
			util.ErrorCheck(diskutil.ReadTop())
		}

	},
}

func init() {
	diskCmd.AddCommand(dtopCmd)
	dtopCmd.Flags().BoolVarP(&write, "write", "w", false, "show top disk write consuming processes")
	dtopCmd.Flags().BoolVarP(&read, "read", "r", false, "show top disk read consuming processes")
}
