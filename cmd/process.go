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
	"github.com/infracloudio/lot/pkg/util/dashboard"
	"github.com/spf13/cobra"
)

var interactive bool

// processCmd represents the process command
var processCmd = &cobra.Command{
	Use:   "process",
	Short: "Command related to process operations",
	Long: `lot process shows the process dashboard.
lot process --help can be run to check subcommands.
lot process <command> runs the specific operation`,
	Run: func(cmd *cobra.Command, args []string) {
		dashboard.ProcessDashboard()
	},
}

func init() {
	processCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "start an interactive shell")
	rootCmd.AddCommand(processCmd)

}
