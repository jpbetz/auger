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
	"io/ioutil"
	"os"

	"github.com/kubernetes-incubator/kvstore-tool/pkg/encoding"
	"github.com/spf13/cobra"

	// TODO: This has a side effect of registering the "" group, which I need.
	// But we should do this in a clear and explicit way.
	_ "k8s.io/kubernetes/pkg/kubeapiserver/options"
)

var (
	decodeLong = `
Decodes kubernetes objects from the binary key-value store encoding used
with etcd 3+.

Outputs data in a variety of formats including YAML, JSON and Protobuf.

YAML and JSON output conversion is performed using api-machinery
serializers and type declarations from the version of kubernetes
source this tool was built against. As a result, output may differ
from what is stored if the type declarations from the kubernetes
version that stored the data and the version of this tool are not
identical. If a type declaration has an incompatible change, or if a
type has been removed entirely, conversion may fail.

The binary format contains an "encoding prefix", an envelope (defined
by runtime.Unknown), and a protobuf payload.  The envelope contains
'meta' fields identifying the payload type.

Protobuf output requires no conversions and returns the exact bytes
of the protobuf payload.`

	decodeExample = `
        ETCDCTL_API=3 etcdctl get /registry/pods/default/<pod-name> \
        --print-value-only | kvstore-tool decode`
)

var decodeCmd = &cobra.Command{
	Use:     "decode",
	Short:   "Decode objects from the kubernetes binary key-value store encoding.",
	Long:    decodeLong,
	Example: decodeExample,
	RunE: func(cmd *cobra.Command, args []string) error {
		return validateAndRun()
	},
}

type decodeOptions struct {
	out           string
	metaOnly      bool
	inputFilename string
}

var options *decodeOptions = &decodeOptions{}

func init() {
	RootCmd.AddCommand(decodeCmd)
	decodeCmd.Flags().StringVarP(&options.out, "output", "o", "yaml", "Output format. One of: json|yaml|proto")
	decodeCmd.Flags().BoolVar(&options.metaOnly, "meta-only", false, "Output only content type and metadata fields")
	decodeCmd.Flags().StringVar(&options.inputFilename, "file", "", "Filename to read storage encoded data from")
}

// Validate the command line flags and run the command.
func validateAndRun() error {
	outMediaType, err := encoding.ToMediaType(options.out)
	if err != nil {
		return err
	}
	in, err := readInput(options.inputFilename)
	if len(in) == 0 {
		return fmt.Errorf("no input data")
	}
	if err != nil {
		return err
	}

	return run(options.metaOnly, outMediaType, in, os.Stdout)
}

// Run the decode command line.
func run(metaOnly bool, outMediaType string, in []byte, out io.Writer) error {
	inMediaType, in, err := encoding.DetectAndExtract(in)
	if err != nil {
		return err
	}

	if metaOnly {
		return encoding.DecodeSummary(inMediaType, in, out)
	}

	return encoding.Convert(inMediaType, outMediaType, in, out)
}

// Readinput reads command line input, either from a provided input file or from stdin.
func readInput(inputFilename string) ([]byte, error) {
	if inputFilename != "" {
		data, err := ioutil.ReadFile(inputFilename)
		if err != nil {
			return nil, fmt.Errorf("error reading input file %s: %v", inputFilename, err)
		}
		data = stripNewline(data)
		return data, nil
	}

	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stdin error: %s", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "warn: waiting on stdin from tty")
	}

	stdin, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("unable to read data from stdin: %v", err)
	}
	// Etcd --print-value-only includes an extranous newline even for binary values.
	// We can safely strip it off since none of the valid inputs this code processes
	// have trailing newline byte.
	stdin = stripNewline(stdin)
	return stdin, nil
}

func stripNewline(d []byte) []byte {
	if len(d) > 0 && d[len(d)-1] == '\n' {
		return d[:len(d)-1]
	} else {
		return d
	}
}
