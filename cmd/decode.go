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

	"bufio"
	"encoding/hex"
	"github.com/kubernetes-incubator/auger/pkg/encoding"
	"github.com/spf13/cobra"
	"bytes"
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
        --print-value-only | auger decode`
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
	batchProcess  bool // special flag to handle incoming etcd-dump-logs output
}

var options *decodeOptions = &decodeOptions{}

func init() {
	RootCmd.AddCommand(decodeCmd)
	decodeCmd.Flags().StringVarP(&options.out, "output", "o", "yaml", "Output format. One of: json|yaml|proto")
	decodeCmd.Flags().BoolVar(&options.metaOnly, "meta-only", false, "Output only content type and metadata fields")
	decodeCmd.Flags().StringVar(&options.inputFilename, "file", "", "Filename to read storage encoded data from")
	decodeCmd.Flags().BoolVar(&options.batchProcess, "batch-process", false, "If set, deccode batch of objects from os.Stdin")
}

// Validate the command line flags and run the command.
func validateAndRun() error {
	outMediaType, err := encoding.ToMediaType(options.out)
	if err != nil {
		return err
	}

	if options.batchProcess {
		return runInBatchMode(options.metaOnly, outMediaType, os.Stdout)
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

// runInBatchMode runs when batchProcess is set to true.
// Original requirement is from etcd WAL log analysis tool etcd-dump-logs,
// (etcd-dump-logs: add decoder support #9790 https://github.com/coreos/etcd/pull/9790)
// to serve as a decoder to decode k8s objects from each entry of the etcd WAL log.
// Read data from os.Stdin, decode object line by line, and print out to os.Stdout.
//
// In etcd-dump-logs, when batchProcess mode is on, two columns are listed for decoder:
// "decoder_status" and "decoded_data". In this case, Auger has two possible output:
// 1. "OK" for decoder_status, actual decoded data for decoded_data
// 2. "ERROR:Auger error" for decoder_status, decoded_data column would be empty in this case.
func runInBatchMode(metaOnly bool, outMediaType string, out io.Writer) (err error) {
	inputReader := bufio.NewReader(os.Stdin)
	lineNum := 0
	for {
		input, err := inputReader.ReadBytes(byte('\n'))
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error reading --batch-process input: %v\n", err)
		}

		input = stripNewline(input)
		decodedinput, err := hex.DecodeString(string(input))
		if err != nil {
			return fmt.Errorf("error decoding input on line %d of --batch-process input: %v", lineNum, err)
		}
		inMediaType, decodedinput, err := encoding.DetectAndExtract(decodedinput)
		if err != nil {
			fmt.Fprintf(out, "ERROR:%v|\n", err)
			continue
		}

		if metaOnly {
			buf := bytes.NewBufferString("")
			err = encoding.DecodeSummary(inMediaType, decodedinput, buf)
			if err != nil {

				fmt.Fprintf(out, "ERROR:%v|\n", err)
			} else {
				fmt.Fprintf(out, "OK|%s\n", buf.String())
			}
			continue
		}

		buf := bytes.NewBufferString("")
		err = encoding.Convert(inMediaType, outMediaType, decodedinput, buf)
		if err != nil {
			fmt.Fprintf(out, "ERROR:%v|\n", err)
		} else {
			fmt.Fprintf(out, "OK|%s\n", buf.String())
		}

		lineNum++
	}
	return nil
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
