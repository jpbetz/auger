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
	"reflect"
	"strconv"
	"strings"

	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/google/safetext/yamltemplate"
	"github.com/jpbetz/auger/pkg/data"
	"github.com/jpbetz/auger/pkg/encoding"
	"github.com/spf13/cobra"
)

var (
	extractLong = `
Extracts kubernetes data stored by etcd into boltdb '.db' files.

May be used both to inspect the contents of a botldb file and to
extract specific data entries. Data may be looked up either by etcd
key and version, or by bolt page and item coordinates.

Etcd must stopped when using this tool, or it will wait indefinitely
for the '.db' file lock.`

	extractExample = `
        # Find an etcd value by it's key and extract it from a boltdb file:
        auger extract -f <boltdb-file> -k /registry/pods/default/<pod-name>

        # List the keys and size of all entries in etcd
        auger extract -f <boltdb-file> --fields=key,value-size

        # Extract a specific field from each kubernetes object
        auger extract -f <boltdb-file> --template="{{.Value.metadata.creationTimestamp}}"

        # Extract kubernetes objects using a filter
        auger extract -f <boltdb-file> --filter=".Value.metadata.namespace=kube-system"

        # Extract the etcd value stored in page 10, item 0 of a boltdb file:
        bolt page --item 0 --value-only <boltdb-file> 10 | auger extract --leaf-item

        # Extract the etcd key stored in page 10, item 0 of a boltdb file:
        bolt page --item 0 --value-only <boltdb-file> 10 | auger extract --leaf-item --print-key
`
)

var extractCmd = &cobra.Command{
	Use:     "extract",
	Short:   "Extracts kubernetes data from the boltdb '.db' files etcd persists to.",
	Long:    extractLong,
	Example: extractExample,
	RunE: func(cmd *cobra.Command, args []string) error {
		return extractValidateAndRun()
	},
}

type extractOptions struct {
	out          string
	filename     string
	key          string
	version      string
	revision     int64
	keyPrefix    string
	listVersions bool
	leafItem     bool
	printKey     bool
	metaSummary  bool
	raw          bool
	fields       string
	template     string
	filter       string
}

var opts *extractOptions = &extractOptions{}

func init() {
	RootCmd.AddCommand(extractCmd)
	extractCmd.Flags().StringVarP(&opts.out, "output", "o", "yaml", "Output format. One of: json|yaml|proto")
	extractCmd.Flags().StringVarP(&opts.filename, "file", "f", "", "Bolt DB '.db' filename")
	extractCmd.Flags().StringVarP(&opts.key, "key", "k", "", "Etcd object key to find in boltdb file")
	extractCmd.Flags().StringVarP(&opts.version, "version", "v", "", "Version of etcd key to find, defaults to latest version")
	extractCmd.Flags().Int64VarP(&opts.revision, "revision", "r", 0, "etcd revision to retrieve data at, if 0, the latest revision is used, defaults to 0")
	extractCmd.Flags().StringVar(&opts.keyPrefix, "keys-by-prefix", "", "List out all keys with the given prefix")
	extractCmd.Flags().BoolVar(&opts.listVersions, "list-versions", false, "List out all versions of the key, requires --key")
	extractCmd.Flags().BoolVar(&opts.leafItem, "leaf-item", false, "Read the input as a boltdb leaf page item.")
	extractCmd.Flags().BoolVar(&opts.printKey, "print-key", false, "Print the key of the matching entry")
	extractCmd.Flags().BoolVar(&opts.metaSummary, "meta-summary", false, "Print a summary of the metadata of the matching entry")
	extractCmd.Flags().BoolVar(&opts.raw, "raw", false, "Don't attempt to decode the etcd value")
	extractCmd.Flags().StringVar(&opts.fields, "fields", Key, fmt.Sprintf("Fields to include when listing entries, comma separated list of: %v", SummaryFields))
	extractCmd.Flags().StringVar(&opts.template, "template", "", fmt.Sprintf("golang template to use when listing entries, see https://golang.org/pkg/text/template, template is provided an object with the fields: %v. The Value field contains the entire kubernetes resource object which also may be dereferenced using a dot seperated path.", templateFields()))
	extractCmd.Flags().StringVar(&opts.filter, "filter", "", fmt.Sprintf("Filter entries using a comma separated list of '<field>=value' constraints. Fields used in filters use the same naming as --template fields, e.g. .Value.metadata.namespace"))
}

const (
	Key                  = "key"
	ValueSize            = "value-size"
	AllVersionsValueSize = "all-versions-value-size"
	VersionCount         = "version-count"
	Value                = "value"
)

var SummaryFields = []string{Key, ValueSize, AllVersionsValueSize, VersionCount, Value}

func templateFields() string {
	t := reflect.ValueOf(data.KeySummary{}).Type()
	names := []string{}
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return strings.Join(names, ", ")
}

func extractValidateAndRun() error {
	outMediaType, err := encoding.ToMediaType(opts.out)
	if err != nil {
		return fmt.Errorf("invalid --output %s: %s", opts.out, err)
	}
	out := os.Stdout
	hasKey := opts.key != ""
	hasVersion := opts.version != ""
	hasKeyPrefix := opts.keyPrefix != ""
	hasFields := opts.fields != Key
	hasTemplate := opts.template != ""

	switch {
	case opts.leafItem:
		raw, err := readInput(opts.filename)
		if err != nil {
			return fmt.Errorf("unable to read input: %s", err)
		}
		kv, err := extractKvFromLeafItem(raw)
		if err != nil {
			return fmt.Errorf("failed to extract etcd key-value record from boltdb leaf item: %s", err)
		}
		if opts.metaSummary {
			return printLeafItemSummary(kv, out)
		} else if opts.printKey {
			return printLeafItemKey(kv, out)
		} else {
			return printLeafItemValue(kv, outMediaType, out)
		}
	case hasKey && hasKeyPrefix:
		return fmt.Errorf("--keys-by-prefix and --key may not be used together")
	case hasKey && opts.listVersions:
		return printVersions(opts.filename, opts.key, out)
	case hasKey:
		return printValue(opts.filename, opts.key, opts.version, opts.raw, outMediaType, out)
	case !hasKey && opts.listVersions:
		return fmt.Errorf("--list-versions may only be used with --key")
	case !hasKey && hasVersion:
		return fmt.Errorf("--version may only be used with --key")
	case hasTemplate && hasFields:
		return fmt.Errorf("--template and --fields may not be used together")
	case hasTemplate:
		return printTemplateSummaries(opts.filename, opts.keyPrefix, opts.revision, opts.template, opts.filter, out)
	default:
		fields := strings.Split(opts.fields, ",")
		return printKeySummaries(opts.filename, opts.keyPrefix, opts.revision, fields, out)
	}
}

// printVersions writes all versions of the given key.
func printVersions(filename string, key string, out io.Writer) error {
	versions, err := data.ListVersions(filename, key)
	if err != nil {
		return err
	}
	for _, v := range versions {
		fmt.Fprintf(out, "%d\n", v)
	}
	return nil
}

// printValue writes the value, in the desired media type, of the given key version.
func printValue(filename string, key string, version string, raw bool, outMediaType string, out io.Writer) error {
	var v int64
	var err error
	if version == "" {
		versions, err := data.ListVersions(filename, key)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			return fmt.Errorf("No versions found for key: %s", key)
		}

		v = maxInSlice(versions)
	} else {
		v, err = strconv.ParseInt(version, 10, 64)
		if err != nil {
			return fmt.Errorf("version must be an int64, but got %s: %s", version, err)
		}
	}
	in, err := data.GetValue(filename, key, v)
	if err != nil {
		return err
	}
	if len(in) == 0 {
		return fmt.Errorf("0 byte value")
	}
	if raw {
		fmt.Fprintf(out, "%s\n", string(in))
		return nil
	}
	_, err = encoding.DetectAndConvert(outMediaType, in, out)
	return err
}

// printLeafItemKey prints an etcd key for a given boltdb leaf item.
func printLeafItemKey(kv *mvccpb.KeyValue, out io.Writer) error {
	fmt.Fprintf(out, "%s\n", kv.Key)
	return nil
}

// printLeafItemSummary prints etcd metadata summary
func printLeafItemSummary(kv *mvccpb.KeyValue, out io.Writer) error {
	fmt.Fprintf(out, "Key: %s\n", kv.Key)
	fmt.Fprintf(out, "Version: %d\n", kv.Version)
	fmt.Fprintf(out, "CreateRevision: %d\n", kv.CreateRevision)
	fmt.Fprintf(out, "ModRevision: %d\n", kv.ModRevision)
	fmt.Fprintf(out, "Lease: %d\n", kv.Lease)
	return nil
}

// printLeafItemValue prints an etcd value for a given boltdb leaf item.
func printLeafItemValue(kv *mvccpb.KeyValue, outMediaType string, out io.Writer) error {
	_, err := encoding.DetectAndConvert(outMediaType, kv.Value, out)
	return err
}

// printKeySummaries prints all keys in the db file with the given key prefix.
func printKeySummaries(filename string, keyPrefix string, revision int64, fields []string, out io.Writer) error {
	if len(fields) == 0 {
		return fmt.Errorf("no fields provided, nothing to output.")
	}

	var hasKey bool
	var hasValue bool
	for _, field := range fields {
		switch field {
		case Key:
			hasKey = true
		case Value:
			hasValue = true
		}
	}
	proj := &data.KeySummaryProjection{HasKey: hasKey, HasValue: hasValue}
	summaries, err := data.ListKeySummaries(filename, []data.Filter{data.NewPrefixFilter(keyPrefix)}, proj, revision)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		summary, err := summarize(s, fields)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", summary)
	}
	return nil
}

// printTemplateSummaries prints out each KeySummary according to the given golang template.
// See https://golang.org/pkg/text/template for details on the template format.
func printTemplateSummaries(filename string, keyPrefix string, revision int64, templatestr string, filterstr string, out io.Writer) error {
	var err error
	t, err := yamltemplate.New("template").Parse(templatestr)
	if err != nil {
		return err
	}

	if len(templatestr) == 0 {
		return fmt.Errorf("no template provided, nothing to output.")
	}

	filters := []data.Filter{}
	if filterstr != "" {
		filters, err = data.ParseFilters(filterstr)
		if err != nil {
			return err
		}
	}

	// We don't have a simple way to determine if the template uses the key or value or not
	summaries, err := data.ListKeySummaries(filename, append(filters, data.NewPrefixFilter(keyPrefix)), &data.KeySummaryProjection{HasKey: true, HasValue: true}, revision)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		err := t.Execute(out, s)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\n")
	}
	return nil
}

func summarize(s *data.KeySummary, fields []string) (string, error) {
	values := make([]string, len(fields))
	for i, field := range fields {
		switch field {
		case Key:
			values[i] = fmt.Sprintf("%s", s.Key)
		case ValueSize:
			values[i] = fmt.Sprintf("%d", s.Stats.ValueSize)
		case AllVersionsValueSize:
			values[i] = fmt.Sprintf("%d", s.Stats.AllVersionsValueSize)
		case VersionCount:
			values[i] = fmt.Sprintf("%d", s.Stats.VersionCount)
		case Value:
			values[i] = fmt.Sprintf("%s", s.ValueJson())
		default:
			return "", fmt.Errorf("unrecognized field: %s", field)
		}
	}
	return strings.Join(values, " "), nil
}

func extractKvFromLeafItem(raw []byte) (*mvccpb.KeyValue, error) {
	kv := &mvccpb.KeyValue{}
	err := kv.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	return kv, nil
}

func maxInSlice(s []int64) int64 {
	r := int64(0)
	for _, e := range s {
		if e > r {
			r = e
		}
	}
	return r
}
