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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/kubernetes/pkg/api"
)

const (
	ProtobufMediaType = "application/vnd.kubernetes.protobuf"
	YamlMediaType     = "application/yaml"
	JsonMediaType     = "application/json"

	ProtobufShortname = "proto"
	YamlShortname     = "yaml"
	JsonShortname     = "json"
)

// See k8s.io/apimachinery/pkg/runtime/serializer/protobuf.go
var ProtoEncodingPrefix = []byte{0x6b, 0x38, 0x73, 0x00}

// ToMediaType maps 'out' flag values to corresponding mime types.
func ToMediaType(out string) (string, error) {
	switch out {
	case YamlShortname:
		return YamlMediaType, nil
	case JsonShortname:
		return JsonMediaType, nil
	case ProtobufShortname:
		return ProtobufMediaType, nil
	default:
		return "", fmt.Errorf("unrecognized 'out' flag value: %v", out)
	}
}

// Convert from kv store encoded data to the given output format using kubernetes' api machinery to
// perform the conversion.
func Convert(inMediaType, outMediaType string, in []byte, out io.Writer) error {

	// TODO: move this elsewhere, I need to be able to use ths function to write data back to etcd or boltdb
	if inMediaType == ProtobufMediaType && outMediaType == ProtobufMediaType {
		return DecodeRaw(in, out)
	}

	typeMeta, err := decodeTypeMeta(inMediaType, in)
	if err != nil {
		return err
	}
	groupName, err := decodeGroupName(typeMeta.APIVersion)
	if err != nil {
		return err
	}
	inCodec, err := newCodec(groupName, inMediaType)
	if err != nil {
		return err
	}
	outCodec, err := newCodec(groupName, outMediaType)
	if err != nil {
		return err
	}

	obj, err := runtime.Decode(inCodec, in)
	if err != nil {
		return err
	}

	encoded, err := runtime.Encode(outCodec, obj)
	if err != nil {
		return err
	}

	_, err = out.Write(encoded)
	if err != nil {
		return err
	}
	return nil
}

// DetectAndExtract searches the the start of either json of protobuf data, and, if found, returns the mime type and data.
func DetectAndExtract(in []byte) (string, []byte, error) {
	if pb, ok := tryFindProto(in); ok {
		return ProtobufMediaType, pb, nil
	}
	if rawJs, ok := tryFindJson(in); ok {
		js, err := rawJs.MarshalJSON()
		if err != nil {
			return "", nil, err
		}
		return JsonMediaType, js, nil
	}
	return "", nil, fmt.Errorf("error reading input, does not appear to contain valid JSON or binary data")
}

// TryFindProto searches for the 'ks8\0' prefix, and, if found, returns the data starting with the prefix.
func tryFindProto(in []byte) ([]byte, bool) {
	i := bytes.Index(in, ProtoEncodingPrefix)
	if i >= 0 && i < len(in) {
		return in[i:], true
	}
	return nil, false
}

const jsonStartChars = "{["

// TryFindJson searches for the start of a valid json substring, and, if found, returns the json.
func tryFindJson(in []byte) (*json.RawMessage, bool) {
	var js json.RawMessage

	i := bytes.IndexAny(in, jsonStartChars)
	for i >= 0 && i < len(in) {
		in = in[i:]
		if len(in) < 2 {
			break
		}
		err := json.Unmarshal(in, &js)
		if err == nil {
			return &js, true
		}
		in = in[1:]
		i = bytes.IndexAny(in, jsonStartChars)
	}
	return nil, false
}

// DecodeRaw decodes the raw payload bytes contained within the 'Unknown' protobuf envelope of
// the given storage data.
func DecodeRaw(in []byte, out io.Writer) error {
	unknown, err := DecodeUnknown(in)
	if err != nil {
		return err
	}
	_, err = out.Write(unknown.Raw)
	if err != nil {
		return fmt.Errorf("failed to write output: %v", err)
	}
	return nil
}

// DecodeSummary decodes the TypeMeta, ContentEncoding and ContentType fields from the 'Unknown'
// protobuf envelope of the given storage data.
func DecodeSummary(inMediaType string, in []byte, out io.Writer) error {
	typeMeta, err := decodeTypeMeta(inMediaType, in)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "MediaType: %s\n", inMediaType)
	fmt.Fprintf(out, "TypeMeta.APIVersion: %s\n", typeMeta.APIVersion)
	fmt.Fprintf(out, "TypeMeta.Kind: %s\n", typeMeta.Kind)
	return nil
}

// DecodeUnknown decodes the Unknown protobuf type from the given storage data.
func DecodeUnknown(in []byte) (*runtime.Unknown, error) {
	if len(in) < 4 {
		return nil, fmt.Errorf("input too short, expected 4 byte proto encoding prefix but got %v", in)
	}
	if !bytes.Equal(in[:4], ProtoEncodingPrefix) {
		return nil, fmt.Errorf("first 4 bytes %v, do not match proto encoding prefix of %v", in[:4], ProtoEncodingPrefix)
	}
	data := in[4:]

	unknown := &runtime.Unknown{}
	if err := unknown.Unmarshal(data); err != nil {
		return nil, err
	}
	return unknown, nil
}

// NewCodec creates a new kubernetes storage codec for encoding and decoding persisted data.
func newCodec(groupName string, mediaType string) (runtime.Codec, error) {
	// Resource is ignored by {Storage,InMemory}EncodingFor, so we only set the group.
	groupResource := schema.GroupResource{Group: groupName}
	resourceEncodingConfig := storage.NewDefaultResourceEncodingConfig(api.Registry)
	storageEncoding, err := resourceEncodingConfig.StorageEncodingFor(groupResource)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage encoding: %v", err)
	}
	memoryEncoding, err := resourceEncodingConfig.InMemoryEncodingFor(groupResource)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize memory encoding: %v", err)
	}
	// TODO: Find a provided initializer for the codec instead of creating the struct directly.
	codec, err := storage.NewStorageCodec(storage.StorageCodecConfig{
		StorageMediaType:  mediaType,
		Config:            storagebackend.Config{Type: storagebackend.StorageTypeETCD3},
		StorageSerializer: api.Codecs,
		StorageVersion:    storageEncoding,
		MemoryVersion:     memoryEncoding,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize codec: %v", err)
	}
	return codec, nil
}

// getTypeMeta gets the TypeMeta from the given data, either as JSON or Protobuf.
func decodeTypeMeta(inMediaType string, in []byte) (*runtime.TypeMeta, error) {
	switch inMediaType {
	case JsonMediaType:
		return typeMetaFromJson(in)
	case ProtobufMediaType:
		return typeMetaFromProto(in)
	default:
		return nil, fmt.Errorf("unsupported inMediaType %s", inMediaType)
	}
}

func typeMetaFromJson(in []byte) (*runtime.TypeMeta, error) {
	var meta runtime.TypeMeta
	json.Unmarshal(in, &meta)
	return &meta, nil
}

func typeMetaFromProto(in []byte) (*runtime.TypeMeta, error) {
	unknown, err := DecodeUnknown(in)
	if err != nil {
		return nil, err
	}
	return &unknown.TypeMeta, nil
}

// decodeGroupName gets a group name from a TypeMeta's apiVersion.
func decodeGroupName(apiVersion string) (string, error) {
	parts := strings.Split(apiVersion, "/")
	switch len(parts) {
	case 1:
		return "", nil
	case 2:
		return parts[0], nil
	default:
		return "", fmt.Errorf("Unrecognized TypeMeta.APIVersion string: %s", apiVersion)
	}
}
