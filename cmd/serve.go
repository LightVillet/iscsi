package cmd

import (
	"fmt"
	"iscsi/iscsi"

	"github.com/spf13/cobra"
)

var IscsiHost string
var IscsiPort string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Create an iSCSI server",
	//Args: cobra.ExactArgs(2),
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
		s.Start()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&IscsiHost, "host", "", "Connection host ip")
	serveCmd.PersistentFlags().StringVar(&IscsiPort, "port", "p", "Connection port")
}
