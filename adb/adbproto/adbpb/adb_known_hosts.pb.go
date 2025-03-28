//
// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: adb_known_hosts.proto

package adbpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Each known host
type HostInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Guid          string                 `protobuf:"bytes,1,opt,name=guid,proto3" json:"guid,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HostInfo) Reset() {
	*x = HostInfo{}
	mi := &file_adb_known_hosts_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HostInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostInfo) ProtoMessage() {}

func (x *HostInfo) ProtoReflect() protoreflect.Message {
	mi := &file_adb_known_hosts_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostInfo.ProtoReflect.Descriptor instead.
func (*HostInfo) Descriptor() ([]byte, []int) {
	return file_adb_known_hosts_proto_rawDescGZIP(), []int{0}
}

func (x *HostInfo) GetGuid() string {
	if x != nil {
		return x.Guid
	}
	return ""
}

// Protobuf definition for the adb_known_hosts.
type AdbKnownHosts struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	HostInfos     []*HostInfo            `protobuf:"bytes,1,rep,name=host_infos,json=hostInfos,proto3" json:"host_infos,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdbKnownHosts) Reset() {
	*x = AdbKnownHosts{}
	mi := &file_adb_known_hosts_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdbKnownHosts) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdbKnownHosts) ProtoMessage() {}

func (x *AdbKnownHosts) ProtoReflect() protoreflect.Message {
	mi := &file_adb_known_hosts_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdbKnownHosts.ProtoReflect.Descriptor instead.
func (*AdbKnownHosts) Descriptor() ([]byte, []int) {
	return file_adb_known_hosts_proto_rawDescGZIP(), []int{1}
}

func (x *AdbKnownHosts) GetHostInfos() []*HostInfo {
	if x != nil {
		return x.HostInfos
	}
	return nil
}

var File_adb_known_hosts_proto protoreflect.FileDescriptor

const file_adb_known_hosts_proto_rawDesc = "" +
	"\n" +
	"\x15adb_known_hosts.proto\x12\tadb.proto\"\x1e\n" +
	"\bHostInfo\x12\x12\n" +
	"\x04guid\x18\x01 \x01(\tR\x04guid\"C\n" +
	"\rAdbKnownHosts\x122\n" +
	"\n" +
	"host_infos\x18\x01 \x03(\v2\x13.adb.proto.HostInfoR\thostInfosB3\n" +
	"\x1dcom.android.server.adb.protosB\x12AdbKnownHostsProtob\x06proto3"

var (
	file_adb_known_hosts_proto_rawDescOnce sync.Once
	file_adb_known_hosts_proto_rawDescData []byte
)

func file_adb_known_hosts_proto_rawDescGZIP() []byte {
	file_adb_known_hosts_proto_rawDescOnce.Do(func() {
		file_adb_known_hosts_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_adb_known_hosts_proto_rawDesc), len(file_adb_known_hosts_proto_rawDesc)))
	})
	return file_adb_known_hosts_proto_rawDescData
}

var file_adb_known_hosts_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_adb_known_hosts_proto_goTypes = []any{
	(*HostInfo)(nil),      // 0: adb.proto.HostInfo
	(*AdbKnownHosts)(nil), // 1: adb.proto.AdbKnownHosts
}
var file_adb_known_hosts_proto_depIdxs = []int32{
	0, // 0: adb.proto.AdbKnownHosts.host_infos:type_name -> adb.proto.HostInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_adb_known_hosts_proto_init() }
func file_adb_known_hosts_proto_init() {
	if File_adb_known_hosts_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_adb_known_hosts_proto_rawDesc), len(file_adb_known_hosts_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_adb_known_hosts_proto_goTypes,
		DependencyIndexes: file_adb_known_hosts_proto_depIdxs,
		MessageInfos:      file_adb_known_hosts_proto_msgTypes,
	}.Build()
	File_adb_known_hosts_proto = out.File
	file_adb_known_hosts_proto_goTypes = nil
	file_adb_known_hosts_proto_depIdxs = nil
}
