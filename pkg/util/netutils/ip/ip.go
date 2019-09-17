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

package ip

import (
	"net"

	"github.com/arush-sal/lot/pkg/util"
)

// Record is a struct that holds ip address along with the interface name
type Record struct {
	IPv4      string
	IPv6      string
	IfaceName string
	Mac       string
	MTU       int
}

// PrivateIPs returns the list of IP addresses from local network interfaces
func PrivateIPs() []Record {
	var result []string
	var records []Record

	ifaces, err := net.Interfaces()
	util.ErrorCheck(err)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		util.ErrorCheck(err)
		var r Record
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPAddr:
				if v.IP.To4() != nil {
					r.IPv4 = v.IP.String()
				} else {
					r.IPv6 = v.IP.String()
				}

			case *net.IPNet:
				ip = v.IP
				if v.IP.To4() != nil {
					r.IPv4 = v.IP.String()
				} else {
					r.IPv6 = v.IP.String()
				}
			}

			result = append(result, ip.String())
		}
		if i.HardwareAddr == nil {
			r.Mac = ""
		} else {
			r.Mac = i.HardwareAddr.String()
		}
		r.IfaceName = i.Name

		r.MTU = i.MTU

		records = append(records, r)
	}
	return records
}
