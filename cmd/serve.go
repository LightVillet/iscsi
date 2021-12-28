/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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
	"iscsi/iscsi"

	"github.com/spf13/cobra"
)

var IscsiHost string
var IscsiPort string

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
	cfg := iscsi.Config{CONN_HOST: IscsiHost, CONN_PORT: IscsiPort}
	s, err := iscsi.NewIscsiConn(cfg)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	if err = s.Start(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	fmt.Println("Success!")
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&IscsiHost, "host", "", "Connection host ip")
	serveCmd.PersistentFlags().StringVar(&IscsiPort, "port", "p", "Connection port")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
