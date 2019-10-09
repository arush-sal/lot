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
	"github.com/infracloudio/lot/pkg/util/netutils"

	"github.com/spf13/cobra"
)

// traceCmd represents the trace command
var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Traces the destination address hop by hop",
	Long:  `lot network trace is a go-lang implementation of traceroot that provides hop by hop information of the path to destination`,
	Run: func(cmd *cobra.Command, args []string) {
		netutils.Trace(args[0])
	},
}

func init() {
	networkCmd.AddCommand(traceCmd)

}
