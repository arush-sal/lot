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
	"github.com/infracloudio/lot/pkg/util/netutils/nettest"
	"github.com/spf13/cobra"
)

// testCmd represents the ip command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Provides IP address for DNS name",
	Long:  `lot network test <DNS name> provides the IPv4 and IPv6 addresses associated with that host name.`,
	Run: func(cmd *cobra.Command, args []string) {
		nettest.NetworkTest(args[0])
	},
}

func init() {
	networkCmd.AddCommand(testCmd)
}
