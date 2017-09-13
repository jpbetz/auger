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

package encoding

import (
	"fmt"
	"testing"
)

var findProtoTests = []struct {
	in       string
	ok       bool
	expected string
}{
	{string(ProtoEncodingPrefix), true, string(ProtoEncodingPrefix)},
	{fmt.Sprintf("xxxxxx%s...end", ProtoEncodingPrefix), true, fmt.Sprintf("%s...end", ProtoEncodingPrefix)},
	{fmt.Sprintf("xxxxxx{}"), false, ""},
}

func TestTryFindProto(t *testing.T) {
	for _, test := range findProtoTests {
		out, ok := tryFindProto([]byte(test.in))
		if test.ok != ok {
			t.Errorf("got ok=%t, want ok=%t for %+v", ok, test.ok, test)
		}
		if ok {
			if string(out) != test.expected {
				t.Errorf("got %s, want %s for %+v", out, test.expected, test)
			}
		}
	}
}

var findJsonTests = []struct {
	in       string
	ok       bool
	expected string
}{
	{"{}", true, "{}"},
	{"[]", true, "[]"},
	{`{"key": "value"}`, true, `{"key": "value"}`},
	{"[1,2,3]", true, "[1,2,3]"},
	{"{}[]{}", true, "{}"},
	{`{"1": {"2": []}}`, true, `{"1": {"2": []}}`},
	{"xxxxxx{}", true, "{}"},
	{"xx{x[x{}", true, "{}"},
	{"xxxxxx[]", true, "[]"},
	{fmt.Sprintf("xxxxxx%s...end", ProtoEncodingPrefix), false, ""},
	{"{}xxxxxx", false, ""},
	{"{}[", false, ""},
}

func TestTryFindJson(t *testing.T) {
	for _, test := range findJsonTests {
		out, ok := tryFindJson([]byte(test.in))
		if test.ok != ok {
			t.Errorf("got ok=%t, want ok=%t for %+v", ok, test.ok, test)
		}
		if ok {
			js, err := out.MarshalJSON()
			if err != nil {
				t.Errorf("unable to marshal json match: %v for %+v", err, test)
			} else if string(js) != test.expected {
				t.Errorf("got %s, want %s for %+v", string(js), test.expected, test)
			}
		}
	}
}
