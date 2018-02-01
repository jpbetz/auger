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
	"strings"
	"testing"

	"github.com/kubernetes-incubator/auger/pkg/encoding"
)

const (
	dbFile            = "testdata/boltdb/db"
	dbWithHistoryFile = "testdata/boltdb/db-with-history"
)

func TestListKeys(t *testing.T) {
	out := new(bytes.Buffer)
	if err := printKeySummaries(dbFile, "", []string{"key"}, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/boltdb/keys.txt")
}

func TestListKeySummaries(t *testing.T) {
	out := new(bytes.Buffer)
	if err := printKeySummaries(dbWithHistoryFile, "", []string{"key", "version-count", "value-size", "all-versions-value-size"}, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/boltdb/keys-with-history.txt")
}

func TestListKeyVersions(t *testing.T) {
	out := new(bytes.Buffer)
	if err := printVersions(dbFile, "/registry/jobs/default/pi", out); err != nil {
		t.Fatal(err)
	}
	s := strings.Trim(out.String(), " \n")
	if s != "3" {
		t.Errorf("got %s, want 3", s)
	}
}

func TestExtractByKey(t *testing.T) {
	out := new(bytes.Buffer)
	if err := printValue(dbFile, "/registry/jobs/default/pi", "3", false, encoding.YamlMediaType, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/yaml/job.yaml")
}

func TestExtractKeyFromLeaf(t *testing.T) {
	kv := readTestFileAsKv(t, "testdata/boltdb/page2item1.bin")
	out := new(bytes.Buffer)
	if err := printLeafItemKey(kv, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/boltdb/page2item1-key.txt")
}

func TestExtractSummaryFromLeaf(t *testing.T) {
	kv := readTestFileAsKv(t, "testdata/boltdb/page2item1.bin")
	out := new(bytes.Buffer)
	if err := printLeafItemSummary(kv, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/boltdb/page2item1-summary.txt")
}

// TODO: run a permutation grid of tests
func TestExtractValueFromLeaf(t *testing.T) {
	kv := readTestFileAsKv(t, "testdata/boltdb/page2item1.bin")
	out := new(bytes.Buffer)
	if err := printLeafItemValue(kv, encoding.YamlMediaType, out); err != nil {
		t.Fatal(err)
	}
	assertMatchesFile(t, out, "testdata/yaml/pod.yaml")
}
