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
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	bolt "github.com/coreos/bbolt"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/kubernetes-incubator/auger/pkg/encoding"
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
	keyPrefix    string
	listVersions bool
	leafItem     bool
	printKey     bool
	metaSummary  bool
	raw          bool
	fields       string
}

var opts *extractOptions = &extractOptions{}

func init() {
	RootCmd.AddCommand(extractCmd)
	extractCmd.Flags().StringVarP(&opts.out, "output", "o", "yaml", "Output format. One of: json|yaml|proto")
	extractCmd.Flags().StringVarP(&opts.filename, "file", "f", "", "Bolt DB '.db' filename")
	extractCmd.Flags().StringVarP(&opts.key, "key", "k", "", "Etcd object key to find in boltdb file")
	extractCmd.Flags().StringVarP(&opts.version, "version", "v", "", "Version of etcd key to find, defaults to latest version")
	extractCmd.Flags().StringVar(&opts.keyPrefix, "keys-by-prefix", "", "List out all keys with the given prefix")
	extractCmd.Flags().BoolVar(&opts.listVersions, "list-versions", false, "List out all versions of the key, requires --key")
	extractCmd.Flags().BoolVar(&opts.leafItem, "leaf-item", false, "Read the input as a boltdb leaf page item.")
	extractCmd.Flags().BoolVar(&opts.printKey, "print-key", false, "Print the key of the matching entry")
	extractCmd.Flags().BoolVar(&opts.metaSummary, "meta-summary", false, "Print a summary of the metadata of the matching entry")
	extractCmd.Flags().BoolVar(&opts.raw, "raw", false, "Don't attempt to decode the etcd value")
	extractCmd.Flags().StringVar(&opts.fields, "fields", Key, fmt.Sprintf("Fields to include when listing entries, comma separated list of: %v", SummaryFields))
}

const (
	Key                  = "key"
	ValueSize            = "value-size"
	AllVersionsValueSize = "all-versions-value-size"
	VersionCount         = "version-count"
)

var SummaryFields = []string{Key, ValueSize, AllVersionsValueSize, VersionCount}

// See etcd/mvcc/kvstore.go:keyBucketName
var keyBucket = []byte("key")

func extractValidateAndRun() error {
	outMediaType, err := encoding.ToMediaType(opts.out)
	if err != nil {
		return fmt.Errorf("invalid --output %s: %s", opts.out, err)
	}
	out := os.Stdout
	hasKey := opts.key != ""
	hasVersion := opts.version != ""
	hasKeyPrefix := opts.keyPrefix != ""

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
	default:
		fields := strings.Split(opts.fields, ",")
		return printKeySummaries(opts.filename, opts.keyPrefix, fields, out)
	}
}

// printVersions writes all versions of the given key.
func printVersions(filename string, key string, out io.Writer) error {
	versions, err := listVersions(filename, key)
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
		versions, err := listVersions(filename, key)
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
	in, err := getValue(filename, key, v)
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
	return convert(outMediaType, in, out)
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
	return convert(outMediaType, kv.Value, out)
}

// printKeySummaries prints all keys in the db file with the given key prefix.
func printKeySummaries(filename string, keyPrefix string, fields []string, out io.Writer) error {
	if len(fields) == 0 {
		return fmt.Errorf("no fields provided, nothing to output.")
	}

	summaries, err := listKeySummaries(filename, keyPrefix)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		summary, err := s.summarize(fields)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", summary)
	}
	return nil
}

func convert(outMediaType string, in []byte, out io.Writer) error {
	inMediaType, in, err := encoding.DetectAndExtract(in)
	if err != nil {
		return err
	}
	return encoding.Convert(inMediaType, outMediaType, in, out)
}

type keySummary struct {
	key                  string
	version              int64
	versionCount         int
	keySize              int
	valueSize            int
	allVersionsKeySize   int
	allVersionsValueSize int
}

func (s *keySummary) summarize(fields []string) (string, error) {
	values := make([]string, len(fields))
	for i, field := range fields {
		switch field {
		case Key:
			values[i] = fmt.Sprintf("%s", s.key)
		case ValueSize:
			values[i] = fmt.Sprintf("%d", s.valueSize)
		case AllVersionsValueSize:
			values[i] = fmt.Sprintf("%d", s.allVersionsValueSize)
		case VersionCount:
			values[i] = fmt.Sprintf("%d", s.versionCount)
		default:
			return "", fmt.Errorf("unrecognized field: %s", field)
		}
	}
	return strings.Join(values, " "), nil
}

func listKeySummaries(filename string, prefix string) ([]*keySummary, error) {
	prefixBytes := []byte(prefix)
	m := make(map[string]*keySummary)
	err := walk(filename, func(kv *mvccpb.KeyValue) (bool, error) {
		if bytes.HasPrefix(kv.Key, prefixBytes) {
			ks, ok := m[string(kv.Key)]
			if !ok {
				ks = &keySummary{
					key:                  string(kv.Key),
					version:              kv.Version,
					keySize:              len(kv.Key),
					valueSize:            len(kv.Value),
					allVersionsKeySize:   len(kv.Key),
					allVersionsValueSize: len(kv.Value),
					versionCount:         1,
				}
				m[string(kv.Key)] = ks
			} else {
				if kv.Version > ks.version {
					ks.version = kv.Version
					ks.valueSize = len(kv.Value)
				}
				ks.versionCount += 1
				ks.allVersionsKeySize += len(kv.Key)
				ks.allVersionsValueSize += len(kv.Value)
			}

		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	result := getSortedKeySummaries(m)
	return result, nil
}

func listVersions(filename string, key string) ([]int64, error) {
	var result []int64

	err := walk(filename, func(kv *mvccpb.KeyValue) (bool, error) {
		if string(kv.Key) == key {
			result = append(result, kv.Version)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// getValue scans the bucket of the bolt db file for a etcd v3 record with the given key and returns the value.
// Because bolt db files are indexed by revision
func getValue(filename string, key string, version int64) ([]byte, error) {
	var result []byte
	found := false
	err := walk(filename, func(kv *mvccpb.KeyValue) (bool, error) {
		if string(kv.Key) == key && kv.Version == version {
			result = kv.Value
			found = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return result, nil
}

func walk(filename string, f func(kv *mvccpb.KeyValue) (bool, error)) error {
	db, err := bolt.Open(filename, 0400, &bolt.Options{})
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(keyBucket)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			kv := &mvccpb.KeyValue{}
			err = kv.Unmarshal(v)
			if err != nil {
				return err
			}
			done, err := f(kv)
			if err != nil {
				return fmt.Errorf("Error handling key %s", kv.Key)
			}
			if done {
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func extractKvFromLeafItem(raw []byte) (*mvccpb.KeyValue, error) {
	kv := &mvccpb.KeyValue{}
	err := kv.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	return kv, nil
}

func getSortedKeySummaries(m map[string]*keySummary) []*keySummary {
	result := make([]*keySummary, len(m))
	i := 0
	for _, v := range m {
		result[i] = v
		i++
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.Compare(result[i].key, result[j].key) <= 0
	})

	return result
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
