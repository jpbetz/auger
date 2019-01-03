/*
Copyright 2017 The Kubernetes Authors.

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
	"io"
	"os"

	"github.com/jpbetz/auger/pkg/encoding"
	"github.com/spf13/cobra"
)

var (
	encodeLong = `
Encodes kubernetes objects to the binary key-value store encoding used
with etcd 3+.
`

	encodeExample = `
	    cat pod.yaml | auger encode | \
	    ETCDCTL_API=3 etcdctl put /registry/pods/default/<pod-name>`
)

var encodeCmd = &cobra.Command{
	Use:     "encode",
	Short:   "Encode objects to the kubernetes binary key-value store encoding.",
	Long:    encodeLong,
	Example: encodeExample,
	RunE: func(cmd *cobra.Command, args []string) error {
		return encodeValidateAndRun()
	},
}

type encodeOptions struct {
	in            string
	inputFilename string
}

var encodeOpts *encodeOptions = &encodeOptions{}

func init() {
	RootCmd.AddCommand(encodeCmd)
	encodeCmd.Flags().StringVarP(&encodeOpts.in, "format", "f", "yaml", "Input format. One of: json|yaml|proto")
	encodeCmd.Flags().StringVar(&encodeOpts.inputFilename, "file", "", "Filename to read input data from")
}

// encodeValidateAndRun validates the command line flags and runs the command.
func encodeValidateAndRun() error {
	// TODO: detect input file type by examining file extension?
	inMediaType, err := encoding.ToMediaType(encodeOpts.in)
	if err != nil {
		return err
	}

	in, err := readInput(encodeOpts.inputFilename)
	if len(in) == 0 {
		return fmt.Errorf("no input data")
	}
	if err != nil {
		return err
	}

	return encodeRun(inMediaType, in, os.Stdout)
}

// encodeRun runs the encode command.
func encodeRun(inMediaType string, in []byte, out io.Writer) error {
	_, err := encoding.Convert(inMediaType, encoding.StorageBinaryMediaType, in, out)
	return err
}
