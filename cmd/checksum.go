package cmd

import (
	"fmt"

	"github.com/jpbetz/auger/pkg/data"
	"github.com/spf13/cobra"
)

var checksumCmd = &cobra.Command{
	Use:   "checksum",
	Short: "Checksum a etcd keyspace.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return checksum()
	},
}

type checksumOptions struct {
	filename string
	revision int64
}

var checksumOpts *checksumOptions = &checksumOptions{}

func init() {
	RootCmd.AddCommand(checksumCmd)
	checksumCmd.Flags().StringVarP(&checksumOpts.filename, "file", "f", "", "Bolt DB '.db' filename")
	checksumCmd.Flags().Int64VarP(&checksumOpts.revision, "revision", "r", 0, "etcd revision to retrieve data at, if 0, the latest revision is used, defaults to 0")
}

func checksum() error {
	checksum, err := data.HashByRevision(checksumOpts.filename, checksumOpts.revision)
	if err != nil {
		return err
	}
	fmt.Printf("checksum: %d\n", checksum.Hash)
	fmt.Printf("compact-revision: %d\n", checksum.CompactRevision)
	fmt.Printf("revision: %d\n", checksum.Revision)
	return nil
}
