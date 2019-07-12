/*
Copyright 2019 The Kubernetes Authors.

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

package data

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"
	"text/template"

	bolt "github.com/coreos/bbolt"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/jpbetz/auger/pkg/encoding"
	"k8s.io/apimachinery/pkg/runtime"
)

// See etcd/mvcc/kvstore.go:keyBucketName
var (
	keyBucket  = []byte("key")
	metaBucket = []byte("meta")

	consistentIndexKeyName  = []byte("consistent_index")
	scheduledCompactKeyName = []byte("scheduledCompactRev")
	finishedCompactKeyName  = []byte("finishedCompactRev")
)

// KeySummary represents a kubernetes object stored in etcd.
type KeySummary struct {
	Key      string
	Version  int64
	Value    interface{}
	TypeMeta *runtime.TypeMeta
	Stats    *KeySummaryStats
}

// KeySummaryStats provides high level statistics on a a particular kubernetes object stored in etcd.
type KeySummaryStats struct {
	VersionCount         int
	KeySize              int
	ValueSize            int
	AllVersionsKeySize   int
	AllVersionsValueSize int
}

// ValueJson gets the json representation of a kubernetes object stored in etcd.
func (ks *KeySummary) ValueJson() string {
	return rawJsonMarshal(ks.Value)
}

// KeySummaryProjection declares which optional fields to include in KeySummary results.
type KeySummaryProjection struct {
	HasKey   bool
	HasValue bool
}

var ProjectEverything = &KeySummaryProjection{HasKey: true, HasValue: true}

// Filter declares an interface for filtering KeySummary results.
type Filter interface {
	Accept(ks *KeySummary) (bool, error)
}

// PrefixFilter filter by key prefix.
type PrefixFilter struct {
	prefix string
}

func NewPrefixFilter(prefix string) *PrefixFilter {
	return &PrefixFilter{prefix}
}

func (ff *PrefixFilter) Accept(ks *KeySummary) (bool, error) {
	return strings.HasPrefix(ks.Key, ff.prefix), nil
}

type ConstraintOp int

const (
	Equals ConstraintOp = iota
)

func (co ConstraintOp) String() string {
	switch co {
	case Equals:
		return "="
	default:
		return fmt.Sprintf("unrecognized enum value %d", co)
	}
}

type FieldConstraint struct {
	lhs string
	op  ConstraintOp
	rhs string
}

func (fc *FieldConstraint) String() string {
	return fmt.Sprintf("%s%s%s", fc.lhs, fc.op.String(), fc.rhs)
}

func (fc *FieldConstraint) BuildFilter() (*FieldFilter, error) {
	t, err := template.New("filter-param").Parse("{{" + fc.lhs + "}}")
	if err != nil {
		return nil, err
	}
	return &FieldFilter{fc, t}, nil
}

// FieldFilter filters according to a field constraint.
type FieldFilter struct {
	*FieldConstraint
	lhsTemplate *template.Template
}

func (ff *FieldFilter) Accept(ks *KeySummary) (bool, error) {
	buf := new(bytes.Buffer)
	err := ff.lhsTemplate.Execute(buf, ks)
	if err != nil {
		return false, fmt.Errorf("failed to look up field in filter %s: %v", ff.lhs, err)
	}
	val := buf.String()
	switch ff.op {
	case Equals:
		return val == ff.rhs, nil
	default:
		return false, fmt.Errorf("Unsupported filter operator: %s", ff.op.String())
	}
}

// HashByRevision returns the checksum and revision that was checksumed of a etcd keyspace.
// If revision is 0, the latest revision is checksumed, else revision is checksumed.
func HashByRevision(filename string, revision int64) (uint32, int64, error) {
	db, err := bolt.Open(filename, 0400, &bolt.Options{})
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()

	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	h.Write(keyBucket)

	latestRevision := revision
	err = walkRevision(db, revision, func(r revKey, kv *mvccpb.KeyValue) (bool, error) {
		if r.main > latestRevision {
			latestRevision = r.main
		}
		h.Write(kv.Key)
		h.Write(kv.Value)
		return false, nil
	})
	if err != nil {
		return 0, 0, err
	}
	return h.Sum32(), latestRevision, nil
}

func getCompactRevision(db *bolt.DB) (int64, error) {
	compactRev := int64(0)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		finishedCompactBytes := b.Get(finishedCompactKeyName)
		if len(finishedCompactBytes) != 0 {
			compactRev = bytesToRev(finishedCompactBytes).main
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return compactRev, nil
}

func getConsistentIndex(db *bolt.DB) (int64, error) {
	consistentIndex := int64(0)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		consistentIndexBytes := b.Get(consistentIndexKeyName)
		if len(consistentIndexBytes) != 0 {
			consistentIndex = int64(binary.BigEndian.Uint64(consistentIndexBytes[0:8]))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return consistentIndex, nil
}

// ListKeySummaries returns a result set with all the provided filters and projections applied.
func ListKeySummaries(filename string, filters []Filter, proj *KeySummaryProjection, revision int64) ([]*KeySummary, error) {
	var err error
	db, err := bolt.Open(filename, 0400, &bolt.Options{})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	prefixFilter, filters := separatePrefixFilter(filters)
	m := make(map[string]*KeySummary)
	err = walk(db, func(r revKey, kv *mvccpb.KeyValue) (bool, error) {
		if revision > 0 && r.main > revision {
			return false, nil
		}
		if r.tombstone {
			delete(m, string(kv.Key))
		}
		prefixAllowed := true
		if prefixFilter != nil {
			prefixAllowed, err = prefixFilter.Accept(&KeySummary{Key: string(kv.Key)})
			if err != nil {
				return false, err
			}
		}
		if prefixAllowed {
			ks, ok := m[string(kv.Key)]
			if !ok {
				buf := new(bytes.Buffer)
				var valJson string
				var typeMeta *runtime.TypeMeta
				var err error
				if typeMeta, err = encoding.DetectAndConvert(encoding.JsonMediaType, kv.Value, buf); err == nil {
					valJson = strings.TrimSpace(buf.String())
				}
				var key string
				var value map[string]interface{}
				if proj.HasKey {
					key = string(kv.Key)
				}
				// If the caller or filters need the value, we need to deserialize it.
				// For filters we don't yet know if they need it, so if there are any filters we must include it.
				if proj.HasValue || len(filters) > 0 {
					value = rawJsonUnmarshal(valJson)
				}
				ks = &KeySummary{
					Key:     key,
					Version: kv.Version,
					Stats: &KeySummaryStats{
						KeySize:              len(kv.Key),
						ValueSize:            len(kv.Value),
						AllVersionsKeySize:   len(kv.Key),
						AllVersionsValueSize: len(kv.Value),
						VersionCount:         1,
					},
					Value:    value,
					TypeMeta: typeMeta,
				}
				for _, filter := range filters {
					ok, err := filter.Accept(ks)
					if err != nil {
						return false, err
					}
					if !ok {
						return false, nil
					}
				}
				m[string(kv.Key)] = ks
			} else {
				if kv.ModRevision > ks.Version {
					ks.Version = kv.ModRevision
					ks.Stats.ValueSize = len(kv.Value)
				}
				ks.Stats.VersionCount += 1
				ks.Stats.AllVersionsKeySize += len(kv.Key)
				ks.Stats.AllVersionsValueSize += len(kv.Value)
			}

		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	result := sortKeySummaries(m)
	return result, nil
}

func sortKeySummaries(m map[string]*KeySummary) []*KeySummary {
	result := make([]*KeySummary, len(m))
	i := 0
	for _, v := range m {
		result[i] = v
		i++
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.Compare(result[i].Key, result[j].Key) <= 0
	})

	return result
}

// ListVersions lists all versions of a object with the given key.
func ListVersions(filename string, key string) ([]int64, error) {
	db, err := bolt.Open(filename, 0400, &bolt.Options{})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var result []int64

	err = walk(db, func(r revKey, kv *mvccpb.KeyValue) (bool, error) {
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

// GetValue scans the bucket of the bolt db file for a etcd v3 record with the given key and returns the value.
// Because bolt db files are indexed by revision
func GetValue(filename string, key string, version int64) ([]byte, error) {
	db, err := bolt.Open(filename, 0400, &bolt.Options{})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var result []byte
	found := false
	err = walk(db, func(r revKey, kv *mvccpb.KeyValue) (bool, error) {
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

func walkRevision(db *bolt.DB, revision int64, f func(r revKey, kv *mvccpb.KeyValue) (bool, error)) error {
	compactRev, err := getCompactRevision(db)
	if err != nil {
		return err
	}
	if revision < compactRev {
		return fmt.Errorf("required revision has been compacted")
	}

	consistentIndex, err := getConsistentIndex(db)
	if err != nil {
		return err
	}

	if revision > consistentIndex {
		return fmt.Errorf("required revision is above latest revision of %d", consistentIndex)
	}

	m := map[string]int64{}
	err = walk(db, func (r revKey, kv *mvccpb.KeyValue) (bool, error) {
		if revision > 0 && r.main > revision {
			return false, nil
		}
		k := string(kv.Key)
		if m[k] < r.main {
			m[k] = r.main
		}
		return false, nil
	})
	if err != nil {
		return err
	}

	return walk(db, func (r revKey, kv *mvccpb.KeyValue) (bool, error) {
		if m[string(kv.Key)] == r.main && !r.tombstone {
			f(r, kv)
		}
		return false, nil
	})
}

func walk(db *bolt.DB, f func(r revKey, kv *mvccpb.KeyValue) (bool, error)) error {
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(keyBucket)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			revision := bytesToRev(k)
			kv := &mvccpb.KeyValue{}
			err := kv.Unmarshal(v)
			if err != nil {
				return err
			}
			done, err := f(revision, kv)
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

// A revKey indicates modification of the key-value space.
// The set of changes that share same main revision changes the key-value space atomically.
type revKey struct {
	// main is the main revision of a set of changes that happen atomically.
	main int64
	// sub is the sub revision of a change in a set of changes that happen
	// atomically. Each change has different increasing sub revision in that
	// set.
	sub int64
	// https://github.com/etcd-io/etcd/blob/2c5162af5c096406fb991b4a15761d186b18afbf/mvcc/kvstore.go#L572
	tombstone bool
}

// revBytesLen is the byte length of a normal revision.
// First 8 bytes is the revision.main in big-endian format. The 9th byte
// is a '_'. The last 8 bytes is the revision.sub in big-endian format.

const (
	revBytesLen            = 8 + 1 + 8
	markedRevBytesLen      = revBytesLen + 1
	markBytePosition       = markedRevBytesLen - 1
	markTombstone     byte = 't'
)

func bytesToRev(bytes []byte) revKey {
	r := revKey{
		main: int64(binary.BigEndian.Uint64(bytes[0:8])),
		sub:  int64(binary.BigEndian.Uint64(bytes[9:])),
	}
	if len(bytes) >= markedRevBytesLen {
		r.tombstone = bytes[markedRevBytesLen-1] == 't'
	}
	return r
}

// ParseFilters parses a comma separated list of '<field>=<value>' filters where each field is
// specified in golang template format, e.g. '.Value.metadata.namespace'.
func ParseFilters(filters string) ([]Filter, error) {
	var results []Filter
	for _, filter := range strings.Split(filters, ",") {
		parts := strings.Split(filter, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("failed to parse filter '%s'", filter)
		}
		lhs := strings.TrimSpace(parts[0])
		rhs := strings.TrimSpace(parts[1])
		fc := &FieldConstraint{lhs: lhs, op: Equals, rhs: rhs}
		f, err := fc.BuildFilter()
		if err != nil {
			return nil, err
		}
		results = append(results, f)
	}
	return results, nil
}

func rawJsonMarshal(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func rawJsonUnmarshal(valJson string) map[string]interface{} {
	val := map[string]interface{}{}
	if err := json.Unmarshal([]byte(valJson), &val); err != nil {
		val = nil
	}
	return val
}

func separatePrefixFilter(filters []Filter) (*PrefixFilter, []Filter) {
	var prefixFilter *PrefixFilter
	remainingFilters := filters
	for i, filter := range filters {
		if pf, ok := filter.(*PrefixFilter); ok {
			prefixFilter = pf
			remainingFilters = append(filters[:i], filters[i+1:]...)
		}
	}
	return prefixFilter, remainingFilters
}
