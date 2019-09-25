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

// usageCmd represents the usage command
var usageCmd = &cobra.Command{
	Use:   "usage",
	Short: "Provide disk usage information of partitions",
	Long:  `lot disk usage provide the disk usage of the partitions`,
	Run: func(cmd *cobra.Command, args []string) {
		util.ErrorCheck(diskutil.PrintUsageStats())
	},
}

func init() {
	diskCmd.AddCommand(usageCmd)

}
