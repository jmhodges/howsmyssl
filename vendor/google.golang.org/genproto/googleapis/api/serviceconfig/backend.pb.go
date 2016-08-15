// Code generated by protoc-gen-go.
// source: google.golang.org/genproto/googleapis/api/serviceconfig/backend.proto
// DO NOT EDIT!

package google_api // import "google.golang.org/genproto/googleapis/api/serviceconfig"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// `Backend` defines the backend configuration for a service.
type Backend struct {
	// A list of backend rules providing configuration for individual API
	// elements.
	Rules []*BackendRule `protobuf:"bytes,1,rep,name=rules" json:"rules,omitempty"`
}

func (m *Backend) Reset()                    { *m = Backend{} }
func (m *Backend) String() string            { return proto.CompactTextString(m) }
func (*Backend) ProtoMessage()               {}
func (*Backend) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{0} }

func (m *Backend) GetRules() []*BackendRule {
	if m != nil {
		return m.Rules
	}
	return nil
}

// A backend rule provides configuration for an individual API element.
type BackendRule struct {
	// Selects the methods to which this rule applies.
	//
	// Refer to [selector][google.api.DocumentationRule.selector] for syntax details.
	Selector string `protobuf:"bytes,1,opt,name=selector" json:"selector,omitempty"`
	// The address of the API backend.
	//
	Address string `protobuf:"bytes,2,opt,name=address" json:"address,omitempty"`
	// The number of seconds to wait for a response from a request.  The
	// default depends on the deployment context.
	Deadline float64 `protobuf:"fixed64,3,opt,name=deadline" json:"deadline,omitempty"`
}

func (m *BackendRule) Reset()                    { *m = BackendRule{} }
func (m *BackendRule) String() string            { return proto.CompactTextString(m) }
func (*BackendRule) ProtoMessage()               {}
func (*BackendRule) Descriptor() ([]byte, []int) { return fileDescriptor2, []int{1} }

func init() {
	proto.RegisterType((*Backend)(nil), "google.api.Backend")
	proto.RegisterType((*BackendRule)(nil), "google.api.BackendRule")
}

func init() {
	proto.RegisterFile("google.golang.org/genproto/googleapis/api/serviceconfig/backend.proto", fileDescriptor2)
}

var fileDescriptor2 = []byte{
	// 207 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x4c, 0x8f, 0x3d, 0x4f, 0x04, 0x21,
	0x10, 0x86, 0x83, 0x17, 0x3d, 0x9d, 0x33, 0x16, 0x34, 0x12, 0xab, 0xcb, 0x55, 0xd7, 0x08, 0x89,
	0x36, 0xd6, 0x9b, 0xd8, 0x6f, 0xf8, 0x03, 0x86, 0x85, 0x91, 0x10, 0x91, 0xd9, 0xc0, 0xea, 0xef,
	0x97, 0xfd, 0x70, 0x6f, 0x1b, 0x92, 0x97, 0xe7, 0x61, 0x98, 0x17, 0xde, 0x3d, 0x91, 0x8f, 0x28,
	0x3d, 0x45, 0x93, 0xbc, 0xa4, 0xec, 0x95, 0xc7, 0xd4, 0x67, 0x1a, 0x48, 0xcd, 0xc8, 0xf4, 0xa1,
	0xa8, 0x7a, 0xa8, 0x82, 0xf9, 0x37, 0x58, 0xb4, 0x94, 0x3e, 0x83, 0x57, 0x9d, 0xb1, 0x5f, 0x98,
	0x9c, 0x9c, 0x54, 0x0e, 0xcb, 0x98, 0xea, 0x9d, 0xde, 0x60, 0xdf, 0xcc, 0x90, 0x3f, 0xc3, 0x75,
	0xfe, 0x89, 0x58, 0x04, 0x3b, 0xee, 0xce, 0x87, 0x97, 0x47, 0x79, 0xd1, 0xe4, 0xe2, 0xe8, 0xca,
	0xf5, 0x6c, 0x9d, 0x3e, 0xe0, 0xb0, 0xb9, 0xe5, 0x4f, 0x70, 0x5b, 0x30, 0xa2, 0x1d, 0x28, 0xd7,
	0x01, 0xec, 0x7c, 0xa7, 0xd7, 0xcc, 0x05, 0xec, 0x8d, 0x73, 0x19, 0x4b, 0x11, 0x57, 0x13, 0xfa,
	0x8f, 0xe3, 0x2b, 0x87, 0xc6, 0xc5, 0x90, 0x50, 0xec, 0x2a, 0x62, 0x7a, 0xcd, 0xcd, 0x11, 0x1e,
	0x2c, 0x7d, 0x6f, 0xb6, 0x68, 0xee, 0x97, 0x0f, 0xdb, 0xb1, 0x46, 0xcb, 0xba, 0x9b, 0xa9, 0xcf,
	0xeb, 0x5f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x99, 0xf6, 0x26, 0x9c, 0x18, 0x01, 0x00, 0x00,
}
