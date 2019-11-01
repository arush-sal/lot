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

// explainCmd represents the explain command
var explainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Provides a detailed example and long descrption of the snippet provided",
	Long:  `lot bpf snippet explain will provides a full detailed explaination along with its respective usage example as described by the original authors for the provided snippet`,
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
			bpfutil.ExplainSnippet(args[0])
		} else {
			fmt.Println("Invalid number of arguments")
			fmt.Println("Use lot bpf snippet explain --help for usage")
			// Refer https://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
			os.Exit(126)
		}

	},
}

func init() {
	snippetCmd.AddCommand(explainCmd)
}
