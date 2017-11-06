// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protobuf.proto

/*
Package trustedentity is a generated protocol buffer package.

It is generated from these files:
	protobuf.proto

It has these top-level messages:
	SecretRequest
	SecretReply
	CACertificateRequest
	CACertificateReply
	CurrentCRLRequest
	CurrentCRLReply
*/
package trustedentity

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// The request message containing the secret name.
type SecretRequest struct {
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

func (m *SecretRequest) Reset()                    { *m = SecretRequest{} }
func (m *SecretRequest) String() string            { return proto.CompactTextString(m) }
func (*SecretRequest) ProtoMessage()               {}
func (*SecretRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *SecretRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// The response message containing the secret
type SecretReply struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *SecretReply) Reset()                    { *m = SecretReply{} }
func (m *SecretReply) String() string            { return proto.CompactTextString(m) }
func (*SecretReply) ProtoMessage()               {}
func (*SecretReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *SecretReply) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

// The request message for the CACertificate.
type CACertificateRequest struct {
}

func (m *CACertificateRequest) Reset()                    { *m = CACertificateRequest{} }
func (m *CACertificateRequest) String() string            { return proto.CompactTextString(m) }
func (*CACertificateRequest) ProtoMessage()               {}
func (*CACertificateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

// The response message containing the CACertificate
type CACertificateReply struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *CACertificateReply) Reset()                    { *m = CACertificateReply{} }
func (m *CACertificateReply) String() string            { return proto.CompactTextString(m) }
func (*CACertificateReply) ProtoMessage()               {}
func (*CACertificateReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *CACertificateReply) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

// The request message for the CRL request.
type CurrentCRLRequest struct {
}

func (m *CurrentCRLRequest) Reset()                    { *m = CurrentCRLRequest{} }
func (m *CurrentCRLRequest) String() string            { return proto.CompactTextString(m) }
func (*CurrentCRLRequest) ProtoMessage()               {}
func (*CurrentCRLRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

// The response message containing the CRL response
type CurrentCRLReply struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *CurrentCRLReply) Reset()                    { *m = CurrentCRLReply{} }
func (m *CurrentCRLReply) String() string            { return proto.CompactTextString(m) }
func (*CurrentCRLReply) ProtoMessage()               {}
func (*CurrentCRLReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *CurrentCRLReply) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func init() {
	proto.RegisterType((*SecretRequest)(nil), "trustedentity.SecretRequest")
	proto.RegisterType((*SecretReply)(nil), "trustedentity.SecretReply")
	proto.RegisterType((*CACertificateRequest)(nil), "trustedentity.CACertificateRequest")
	proto.RegisterType((*CACertificateReply)(nil), "trustedentity.CACertificateReply")
	proto.RegisterType((*CurrentCRLRequest)(nil), "trustedentity.CurrentCRLRequest")
	proto.RegisterType((*CurrentCRLReply)(nil), "trustedentity.CurrentCRLReply")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for SecretKeeper service

type SecretKeeperClient interface {
	// Sends a request for a secret
	SaySecret(ctx context.Context, in *SecretRequest, opts ...grpc.CallOption) (*SecretReply, error)
	// Sends a request for a CACertificate
	SayCACertificate(ctx context.Context, in *CACertificateRequest, opts ...grpc.CallOption) (*CACertificateReply, error)
	// Sends a request for a CACertificate
	SayCurrentCRL(ctx context.Context, in *CurrentCRLRequest, opts ...grpc.CallOption) (*CurrentCRLReply, error)
}

type secretKeeperClient struct {
	cc *grpc.ClientConn
}

func NewSecretKeeperClient(cc *grpc.ClientConn) SecretKeeperClient {
	return &secretKeeperClient{cc}
}

func (c *secretKeeperClient) SaySecret(ctx context.Context, in *SecretRequest, opts ...grpc.CallOption) (*SecretReply, error) {
	out := new(SecretReply)
	err := grpc.Invoke(ctx, "/trustedentity.SecretKeeper/SaySecret", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *secretKeeperClient) SayCACertificate(ctx context.Context, in *CACertificateRequest, opts ...grpc.CallOption) (*CACertificateReply, error) {
	out := new(CACertificateReply)
	err := grpc.Invoke(ctx, "/trustedentity.SecretKeeper/SayCACertificate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *secretKeeperClient) SayCurrentCRL(ctx context.Context, in *CurrentCRLRequest, opts ...grpc.CallOption) (*CurrentCRLReply, error) {
	out := new(CurrentCRLReply)
	err := grpc.Invoke(ctx, "/trustedentity.SecretKeeper/SayCurrentCRL", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for SecretKeeper service

type SecretKeeperServer interface {
	// Sends a request for a secret
	SaySecret(context.Context, *SecretRequest) (*SecretReply, error)
	// Sends a request for a CACertificate
	SayCACertificate(context.Context, *CACertificateRequest) (*CACertificateReply, error)
	// Sends a request for a CACertificate
	SayCurrentCRL(context.Context, *CurrentCRLRequest) (*CurrentCRLReply, error)
}

func RegisterSecretKeeperServer(s *grpc.Server, srv SecretKeeperServer) {
	s.RegisterService(&_SecretKeeper_serviceDesc, srv)
}

func _SecretKeeper_SaySecret_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SecretRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecretKeeperServer).SaySecret(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trustedentity.SecretKeeper/SaySecret",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecretKeeperServer).SaySecret(ctx, req.(*SecretRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecretKeeper_SayCACertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CACertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecretKeeperServer).SayCACertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trustedentity.SecretKeeper/SayCACertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecretKeeperServer).SayCACertificate(ctx, req.(*CACertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecretKeeper_SayCurrentCRL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CurrentCRLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecretKeeperServer).SayCurrentCRL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trustedentity.SecretKeeper/SayCurrentCRL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecretKeeperServer).SayCurrentCRL(ctx, req.(*CurrentCRLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _SecretKeeper_serviceDesc = grpc.ServiceDesc{
	ServiceName: "trustedentity.SecretKeeper",
	HandlerType: (*SecretKeeperServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SaySecret",
			Handler:    _SecretKeeper_SaySecret_Handler,
		},
		{
			MethodName: "SayCACertificate",
			Handler:    _SecretKeeper_SayCACertificate_Handler,
		},
		{
			MethodName: "SayCurrentCRL",
			Handler:    _SecretKeeper_SayCurrentCRL_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protobuf.proto",
}

func init() { proto.RegisterFile("protobuf.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 276 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0x4f, 0x4b, 0xf3, 0x40,
	0x10, 0xc6, 0xdf, 0xbc, 0x88, 0xd2, 0xd1, 0xa8, 0x1d, 0x45, 0x4a, 0x90, 0x52, 0xb7, 0x07, 0x05,
	0x61, 0x0f, 0x8a, 0x1f, 0xc0, 0xe6, 0xe0, 0x41, 0x0f, 0x25, 0xb9, 0x7a, 0xd9, 0xc6, 0x69, 0x09,
	0xe4, 0xcf, 0xba, 0x3b, 0x01, 0xf7, 0x2b, 0xf8, 0xa9, 0xa5, 0x89, 0x91, 0x26, 0x68, 0x6e, 0x93,
	0x27, 0xcf, 0xf3, 0x63, 0xe7, 0x61, 0xe0, 0x58, 0x9b, 0x92, 0xcb, 0x55, 0xb5, 0x96, 0xf5, 0x80,
	0x3e, 0x9b, 0xca, 0x32, 0xbd, 0x51, 0xc1, 0x29, 0x3b, 0x31, 0x07, 0x3f, 0xa6, 0xc4, 0x10, 0x47,
	0xf4, 0x5e, 0x91, 0x65, 0x44, 0xd8, 0x2b, 0x54, 0x4e, 0x13, 0x6f, 0xe6, 0xdd, 0x8c, 0xa2, 0x7a,
	0x16, 0xd7, 0x70, 0xd8, 0x9a, 0x74, 0xe6, 0x70, 0x02, 0x07, 0x39, 0x59, 0xab, 0x36, 0xad, 0xab,
	0xfd, 0x14, 0x17, 0x70, 0x1e, 0x3e, 0x86, 0x64, 0x38, 0x5d, 0xa7, 0x89, 0x62, 0xfa, 0x86, 0x0a,
	0x09, 0xd8, 0xd3, 0x87, 0x39, 0x67, 0x30, 0x0e, 0x2b, 0x63, 0xa8, 0xe0, 0x30, 0x7a, 0x69, 0x21,
	0xb7, 0x70, 0xb2, 0x2b, 0x0e, 0x12, 0xee, 0x3e, 0xff, 0xc3, 0x51, 0xf3, 0xe6, 0x67, 0x22, 0x4d,
	0x06, 0x9f, 0x60, 0x14, 0x2b, 0xd7, 0x48, 0x78, 0x29, 0x3b, 0x2d, 0xc8, 0x4e, 0x05, 0x41, 0xf0,
	0xc7, 0x5f, 0x9d, 0x39, 0xf1, 0x0f, 0x5f, 0xe1, 0x34, 0x56, 0xae, 0xb3, 0x0e, 0xce, 0x7b, 0x89,
	0xdf, 0x4a, 0x08, 0xae, 0x86, 0x4d, 0x0d, 0x3d, 0x06, 0x7f, 0x4b, 0xff, 0xd9, 0x13, 0x67, 0xfd,
	0x54, 0xbf, 0x97, 0x60, 0x3a, 0xe0, 0xa8, 0xa1, 0x8b, 0x07, 0x98, 0xa6, 0xa5, 0xdc, 0x18, 0x9d,
	0x48, 0xfa, 0x50, 0xb9, 0xce, 0xc8, 0x76, 0x33, 0x8b, 0xf1, 0x6e, 0x57, 0xcb, 0xed, 0xa1, 0x2c,
	0xbd, 0xd5, 0x7e, 0x7d, 0x31, 0xf7, 0x5f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x94, 0x91, 0x97, 0x3d,
	0x43, 0x02, 0x00, 0x00,
}