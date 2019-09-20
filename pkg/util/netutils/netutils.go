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

This code largely comes from https://github.com/aeden/traceroute which is
licensed under MIT license.
*/

package netutils

import (
	"fmt"
	"net"
	"os"
	"text/tabwriter"

	"github.com/arush-sal/lot/pkg/util/netutils/ip"
	"github.com/arush-sal/lot/pkg/util/netutils/traceroute"
)

// Trace is an exported function that traces the given address
func Trace(host string) {
	options := traceroute.TracerouteOptions{}
	options.SetRetries(1)
	options.SetMaxHops(64)
	options.SetFirstHop(1)

	ipAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return
	}

	fmt.Printf("traceroute to %v (%v), %v hops max, %v byte packets\n", host, ipAddr, options.MaxHops(), options.PacketSize())

	c := make(chan traceroute.TracerouteHop, 0)
	go func() {
		for {
			hop, ok := <-c
			if !ok {
				fmt.Println()
				return
			}
			printHop(hop)
		}
	}()

	_, err = traceroute.Traceroute(host, &options, c)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
}

func printHop(hop traceroute.TracerouteHop) {
	addr := fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
	hostOrAddr := addr
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	if hop.Success {
		fmt.Printf("%-3d %v (%v)  %v\n", hop.TTL, hostOrAddr, addr, hop.ElapsedTime)
	} else {
		fmt.Printf("%-3d *\n", hop.TTL)
	}
}

// PrintIPs prints the provided IP addresses
func PrintIPs(ipList []ip.Record) {

	fmt.Println()
	const format = "|%d\t|%s\t|%s\t|%s\t|%s\t|%d\t\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 2, ' ', 0)

	for idx, val := range ipList {
		// fmt.Println(idx, ":", val)
		fmt.Fprintf(tw, format, idx, val.IPv4, val.IPv6, val.IfaceName, val.Mac, val.MTU)
	}
	tw.Flush()
}

// PrintPublicIP prints the provided public IP addresses
func PrintPublicIP(addr string) {
	fmt.Println()
	const format = "|%s\t|%s\n"
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, format, "Public IP: ", addr)
	tw.Flush()
}
