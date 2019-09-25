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
	"github.com/arush-sal/lot/pkg/util/procutil"
	"github.com/spf13/cobra"
)

var cpu, ram bool

// topCmd represents the top command
var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Provides the information about top resource consuming processes",
	Long:  `lot process top provides the information about the top process by their cpu or memory consumption`,
	Run: func(cmd *cobra.Command, args []string) {
		if (cpu && ram) || (!cpu && !ram) {
			util.ErrorCheck(procutil.CPUTop())
		}
		if cpu {
			util.ErrorCheck(procutil.CPUTop())
		}
		if ram {
			util.ErrorCheck(procutil.MemTop())
		}
	},
}

func init() {
	topCmd.Flags().BoolVarP(&cpu, "cpu", "c", false, "start an interactive shell")
	topCmd.Flags().BoolVarP(&ram, "ram", "r", false, "start an interactive shell")
	processCmd.AddCommand(topCmd)

}
