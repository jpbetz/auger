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
	"testing"

	"github.com/kubernetes-incubator/auger/pkg/encoding"
)

var encodeTests = []struct {
	fileIn       string
	fileExpected string
	inMediaType  string
}{
	{"testdata/yaml/pod.yaml", "testdata/storage/pod.bin", encoding.YamlMediaType},
	{"testdata/json/pod.json", "testdata/storage/pod.bin", encoding.JsonMediaType},
	{"testdata/yaml/job.yaml", "testdata/storage/job.bin", encoding.YamlMediaType},
	{"testdata/json/job.json", "testdata/storage/job.bin", encoding.JsonMediaType},
}

func TestEncode(t *testing.T) {
	for _, test := range encodeTests {
		in := readTestFile(t, test.fileIn)
		out := new(bytes.Buffer)
		if err := encodeRun(test.inMediaType, in, out); err != nil {
			t.Errorf("%v for %+v", err, test)
			continue
		}
		rt := new(bytes.Buffer)
		if err := run(false, test.inMediaType, out.Bytes(), rt); err != nil {
			t.Errorf("%v for round trip of %+v", err, test)
			continue
		}
		b := rt.Bytes()
		if !bytes.Equal(b, in) {
			t.Errorf("for round trip of %s, got:\n%s\nwanted:\n%s\n", test.fileIn, b, in)
		}
	}
}
