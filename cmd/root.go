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
	// "fmt"
	"fmt"
	"os"
	"os/user"

	// "os/user"

	// "github.com/arush-sal/lot/pkg/utils"
	"github.com/arush-sal/lot/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	interactive bool
	environment string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "lot",
	Short:   "",
	Version: "v0.0.1",
	Long:    ``,
	// Run: func(cmd *cobra.Command, args []string) {
	// 	allCmd.Execute()
	// },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	usr, err := user.Current()
	utils.ErrorCheck(err)

	if usr.Uid != "0" {
		utils.ErrorCheck(fmt.Errorf("Needs root privileges to run"))
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "start an interactive shell")
	rootCmd.PersistentFlags().StringVarP(&environment, "env", "", "host", "environment in which lot is executed\nvalid options: k8s, container, swarm, host")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
}
