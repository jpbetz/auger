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
	"io/ioutil"
	"os"
	"testing"

	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/kubernetes-incubator/kvstore-tool/pkg/encoding"
)

var decodeTests = []struct {
	fileIn       string
	fileExpected string

	metaOnly     bool
	outMediaType string
}{
	// Pod is in the 'core' group
	{"testdata/storage/pod.bin", "testdata/yaml/pod.yaml", false, encoding.YamlMediaType},
	{"testdata/storage/pod.bin", "testdata/json/pod.json", false, encoding.JsonMediaType},
	{"testdata/storage/pod.bin", "testdata/proto/pod.bin", false, encoding.ProtobufMediaType},
	{"testdata/storage/pod.bin", "testdata/meta/pod.txt", true, encoding.YamlMediaType},

	// Job is in the 'batch' group
	{"testdata/storage/job.bin", "testdata/yaml/job.yaml", false, encoding.YamlMediaType},
	{"testdata/storage/job.bin", "testdata/json/job.json", false, encoding.JsonMediaType},
	{"testdata/storage/job.bin", "testdata/proto/job.bin", false, encoding.ProtobufMediaType},
	{"testdata/storage/job.bin", "testdata/meta/job.txt", true, encoding.YamlMediaType},

	// JSON
	{"testdata/json/pod.json", "testdata/json/pod.json", false, encoding.JsonMediaType},

	// With etcd key
	{"testdata/storage/pod-with-key.bin", "testdata/yaml/pod.yaml", false, encoding.YamlMediaType},
	{"testdata/json/pod-with-key.txt", "testdata/json/pod.json", false, encoding.JsonMediaType},
}

func TestDecode(t *testing.T) {
	for _, test := range decodeTests {
		in := readTestFile(t, test.fileIn)
		in = in[:len(in)-1]
		out := new(bytes.Buffer)
		if err := run(test.metaOnly, test.outMediaType, in, out); err != nil {
			t.Fatalf("%v for %+v", err, test)
		}
		assertMatchesFile(t, out, test.fileExpected)
	}
}

func assertMatchesFile(t *testing.T, out *bytes.Buffer, filename string) {
	b := out.Bytes()
	expected := readTestFile(t, filename)
	if !bytes.Equal(b, expected) {
		t.Errorf(`got input of length %d, wanted input of length %d
==== BEGIN RECIEVED FILE ====
%s
====END RECIEVED FILE ====
====BEGIN EXPECTED FILE ====
%s
==== END EXPECTED FILE ====
`, len(b), len(expected), b, expected)
	}
}

func readTestFile(t *testing.T, filename string) []byte {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("failed to open test data file: %v", err)
	}
	in, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read test data file, %v", err)
	}
	return in
}

func readTestFileAsKv(t *testing.T, filename string) *mvccpb.KeyValue {
	kv, err := extractKvFromLeafItem(readTestFile(t, filename))
	if err != nil {
		t.Fatalf("failed to extract etcd key-value record from boltdb leaf item: %s", err)
	}
	return kv
}
