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
	"github.com/infracloudio/lot/pkg/util/netutils/ip"
	"github.com/spf13/cobra"
)

// ipCmd represents the ip command
var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Provides public and private IP Addresses of the system",
	Long:  `lot network ip lists the private IP Adresses (v4 & v6) along with their interface names.
It also lists the hardware address of the interface and the MTU.`,
	Run: func(cmd *cobra.Command, args []string) {
		records := ip.PrivateIPs()
		netutils.PrintIPs(records)
		netutils.PrintPublicIP(ip.PublicIP())
	},
}

func init() {
	networkCmd.AddCommand(ipCmd)

}
