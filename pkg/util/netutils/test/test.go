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

package test

import (
        "fmt"
	"os"
        "net"
        "strconv"

	//"golang.org/x/net/icmp"
	//"golang.org/x/net/ipv4"
)

type packet struct {
        bytes  []byte
        nbytes int
        ttl    int
}

func NetworkTest (args string) {
	fmt.Println("")
	if net.ParseIP(args) == nil {
		fmt.Println("Provided argument is not an ip address. Doing a look up for host name")
		lookupName(args)
	} else {
		lookupIp(args)
		ping(args)
	}
}

func lookupName (name string) {
	addrs, err := net.LookupHost(name)
	if err != nil {
		fmt.Println("Error looking up", name, ":", err)
		os.Exit(1)
	}
	fmt.Println("Host name: ", name)
	for indx, addr := range addrs {
		fmt.Println("Address number " + strconv.Itoa(indx) + ": " + addr)
	}
	ping(fmt.Sprintf("%s", addrs[0]))
}

func lookupIp (addr string) {
	names, err := net.LookupAddr(addr)
	if err != nil {
                fmt.Println("Error looking up", addr, ":", err)
                os.Exit(1)
        }
        fmt.Println("IP Addr: ", addr)
        for indx, name := range names {
                fmt.Println("Host name  " + strconv.Itoa(indx) + ": " + name)
        }
}

func ping (addr string) {
	fmt.Println("Pinging ", addr)
}
