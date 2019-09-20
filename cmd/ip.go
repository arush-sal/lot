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
	"github.com/arush-sal/lot/pkg/util/netutils"
	"github.com/arush-sal/lot/pkg/util/netutils/ip"
	"github.com/spf13/cobra"
)

// ipCmd represents the ip command
var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		records := ip.PrivateIPs()
		netutils.PrintIPs(records)
		netutils.PrintPublicIP(ip.PublicIP())
	},
}

func init() {
	networkCmd.AddCommand(ipCmd)

}
