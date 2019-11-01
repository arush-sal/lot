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
	"fmt"
	"os"

	"github.com/infracloudio/lot/pkg/util/bpfutil"
	"github.com/spf13/cobra"
)

// snippetCmd represents the snippet command
var snippetCmd = &cobra.Command{
	Use:   "snippet",
	Short: "Executes the provided bpftrace snippet",
	Long:  `lot bpf snippet is a wrapper around bpftrace through which you can execute any bpftrace script or you can choose one from the list of provided scripts`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Missing bpftrace snippet")
			fmt.Println("Use the list sub-command to get a list of out-of-box eBPF snippets")
			os.Exit(0)
		}

		if len(args) == 1 {
			if !bpfutil.IsValidSnippet(args[0]) {
				fmt.Printf("Not a valid bpftrace snippet\n\n")
				bpfutil.ListSnippets()
				os.Exit(0)
			}
			bpfutil.ExecuteSnippet(args[0])
		} else {
			fmt.Println("Invalid number of arguments")
			fmt.Println("Use lot bpf snippet --help for usage")
			// Refer https://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
			os.Exit(126)
		}

	},
}

func init() {
	bpfCmd.AddCommand(snippetCmd)

}
