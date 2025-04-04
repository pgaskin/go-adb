//
// Copyright (C) 2023 The Android Open Source Project
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
// source: adb_host.proto

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

// This mirrors adb.h's "enum ConnectionState"
type ConnectionState int32

const (
	ConnectionState_ANY          ConnectionState = 0
	ConnectionState_CONNECTING   ConnectionState = 1
	ConnectionState_AUTHORIZING  ConnectionState = 2
	ConnectionState_UNAUTHORIZED ConnectionState = 3
	ConnectionState_NOPERMISSION ConnectionState = 4
	ConnectionState_DETACHED     ConnectionState = 5
	ConnectionState_OFFLINE      ConnectionState = 6
	ConnectionState_BOOTLOADER   ConnectionState = 7
	ConnectionState_DEVICE       ConnectionState = 8
	ConnectionState_HOST         ConnectionState = 9
	ConnectionState_RECOVERY     ConnectionState = 10
	ConnectionState_SIDELOAD     ConnectionState = 11
	ConnectionState_RESCUE       ConnectionState = 12
)

// Enum value maps for ConnectionState.
var (
	ConnectionState_name = map[int32]string{
		0:  "ANY",
		1:  "CONNECTING",
		2:  "AUTHORIZING",
		3:  "UNAUTHORIZED",
		4:  "NOPERMISSION",
		5:  "DETACHED",
		6:  "OFFLINE",
		7:  "BOOTLOADER",
		8:  "DEVICE",
		9:  "HOST",
		10: "RECOVERY",
		11: "SIDELOAD",
		12: "RESCUE",
	}
	ConnectionState_value = map[string]int32{
		"ANY":          0,
		"CONNECTING":   1,
		"AUTHORIZING":  2,
		"UNAUTHORIZED": 3,
		"NOPERMISSION": 4,
		"DETACHED":     5,
		"OFFLINE":      6,
		"BOOTLOADER":   7,
		"DEVICE":       8,
		"HOST":         9,
		"RECOVERY":     10,
		"SIDELOAD":     11,
		"RESCUE":       12,
	}
)

func (x ConnectionState) Enum() *ConnectionState {
	p := new(ConnectionState)
	*p = x
	return p
}

func (x ConnectionState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConnectionState) Descriptor() protoreflect.EnumDescriptor {
	return file_adb_host_proto_enumTypes[0].Descriptor()
}

func (ConnectionState) Type() protoreflect.EnumType {
	return &file_adb_host_proto_enumTypes[0]
}

func (x ConnectionState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConnectionState.Descriptor instead.
func (ConnectionState) EnumDescriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{0}
}

type ConnectionType int32

const (
	ConnectionType_UNKNOWN ConnectionType = 0
	ConnectionType_USB     ConnectionType = 1
	ConnectionType_SOCKET  ConnectionType = 2
)

// Enum value maps for ConnectionType.
var (
	ConnectionType_name = map[int32]string{
		0: "UNKNOWN",
		1: "USB",
		2: "SOCKET",
	}
	ConnectionType_value = map[string]int32{
		"UNKNOWN": 0,
		"USB":     1,
		"SOCKET":  2,
	}
)

func (x ConnectionType) Enum() *ConnectionType {
	p := new(ConnectionType)
	*p = x
	return p
}

func (x ConnectionType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConnectionType) Descriptor() protoreflect.EnumDescriptor {
	return file_adb_host_proto_enumTypes[1].Descriptor()
}

func (ConnectionType) Type() protoreflect.EnumType {
	return &file_adb_host_proto_enumTypes[1]
}

func (x ConnectionType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConnectionType.Descriptor instead.
func (ConnectionType) EnumDescriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{1}
}

type AdbServerStatus_UsbBackend int32

const (
	AdbServerStatus_UNKNOWN_USB AdbServerStatus_UsbBackend = 0
	AdbServerStatus_NATIVE      AdbServerStatus_UsbBackend = 1
	AdbServerStatus_LIBUSB      AdbServerStatus_UsbBackend = 2
)

// Enum value maps for AdbServerStatus_UsbBackend.
var (
	AdbServerStatus_UsbBackend_name = map[int32]string{
		0: "UNKNOWN_USB",
		1: "NATIVE",
		2: "LIBUSB",
	}
	AdbServerStatus_UsbBackend_value = map[string]int32{
		"UNKNOWN_USB": 0,
		"NATIVE":      1,
		"LIBUSB":      2,
	}
)

func (x AdbServerStatus_UsbBackend) Enum() *AdbServerStatus_UsbBackend {
	p := new(AdbServerStatus_UsbBackend)
	*p = x
	return p
}

func (x AdbServerStatus_UsbBackend) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AdbServerStatus_UsbBackend) Descriptor() protoreflect.EnumDescriptor {
	return file_adb_host_proto_enumTypes[2].Descriptor()
}

func (AdbServerStatus_UsbBackend) Type() protoreflect.EnumType {
	return &file_adb_host_proto_enumTypes[2]
}

func (x AdbServerStatus_UsbBackend) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AdbServerStatus_UsbBackend.Descriptor instead.
func (AdbServerStatus_UsbBackend) EnumDescriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{2, 0}
}

type AdbServerStatus_MdnsBackend int32

const (
	AdbServerStatus_UNKNOWN_MDNS AdbServerStatus_MdnsBackend = 0
	AdbServerStatus_BONJOUR      AdbServerStatus_MdnsBackend = 1
	AdbServerStatus_OPENSCREEN   AdbServerStatus_MdnsBackend = 2
)

// Enum value maps for AdbServerStatus_MdnsBackend.
var (
	AdbServerStatus_MdnsBackend_name = map[int32]string{
		0: "UNKNOWN_MDNS",
		1: "BONJOUR",
		2: "OPENSCREEN",
	}
	AdbServerStatus_MdnsBackend_value = map[string]int32{
		"UNKNOWN_MDNS": 0,
		"BONJOUR":      1,
		"OPENSCREEN":   2,
	}
)

func (x AdbServerStatus_MdnsBackend) Enum() *AdbServerStatus_MdnsBackend {
	p := new(AdbServerStatus_MdnsBackend)
	*p = x
	return p
}

func (x AdbServerStatus_MdnsBackend) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AdbServerStatus_MdnsBackend) Descriptor() protoreflect.EnumDescriptor {
	return file_adb_host_proto_enumTypes[3].Descriptor()
}

func (AdbServerStatus_MdnsBackend) Type() protoreflect.EnumType {
	return &file_adb_host_proto_enumTypes[3]
}

func (x AdbServerStatus_MdnsBackend) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AdbServerStatus_MdnsBackend.Descriptor instead.
func (AdbServerStatus_MdnsBackend) EnumDescriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{2, 1}
}

type Device struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Serial          string                 `protobuf:"bytes,1,opt,name=serial,proto3" json:"serial,omitempty"`
	State           ConnectionState        `protobuf:"varint,2,opt,name=state,proto3,enum=adb.proto.ConnectionState" json:"state,omitempty"`
	BusAddress      string                 `protobuf:"bytes,3,opt,name=bus_address,json=busAddress,proto3" json:"bus_address,omitempty"`
	Product         string                 `protobuf:"bytes,4,opt,name=product,proto3" json:"product,omitempty"`
	Model           string                 `protobuf:"bytes,5,opt,name=model,proto3" json:"model,omitempty"`
	Device          string                 `protobuf:"bytes,6,opt,name=device,proto3" json:"device,omitempty"`
	ConnectionType  ConnectionType         `protobuf:"varint,7,opt,name=connection_type,json=connectionType,proto3,enum=adb.proto.ConnectionType" json:"connection_type,omitempty"`
	NegotiatedSpeed int64                  `protobuf:"varint,8,opt,name=negotiated_speed,json=negotiatedSpeed,proto3" json:"negotiated_speed,omitempty"`
	MaxSpeed        int64                  `protobuf:"varint,9,opt,name=max_speed,json=maxSpeed,proto3" json:"max_speed,omitempty"`
	TransportId     int64                  `protobuf:"varint,10,opt,name=transport_id,json=transportId,proto3" json:"transport_id,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *Device) Reset() {
	*x = Device{}
	mi := &file_adb_host_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Device) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Device) ProtoMessage() {}

func (x *Device) ProtoReflect() protoreflect.Message {
	mi := &file_adb_host_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Device.ProtoReflect.Descriptor instead.
func (*Device) Descriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{0}
}

func (x *Device) GetSerial() string {
	if x != nil {
		return x.Serial
	}
	return ""
}

func (x *Device) GetState() ConnectionState {
	if x != nil {
		return x.State
	}
	return ConnectionState_ANY
}

func (x *Device) GetBusAddress() string {
	if x != nil {
		return x.BusAddress
	}
	return ""
}

func (x *Device) GetProduct() string {
	if x != nil {
		return x.Product
	}
	return ""
}

func (x *Device) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *Device) GetDevice() string {
	if x != nil {
		return x.Device
	}
	return ""
}

func (x *Device) GetConnectionType() ConnectionType {
	if x != nil {
		return x.ConnectionType
	}
	return ConnectionType_UNKNOWN
}

func (x *Device) GetNegotiatedSpeed() int64 {
	if x != nil {
		return x.NegotiatedSpeed
	}
	return 0
}

func (x *Device) GetMaxSpeed() int64 {
	if x != nil {
		return x.MaxSpeed
	}
	return 0
}

func (x *Device) GetTransportId() int64 {
	if x != nil {
		return x.TransportId
	}
	return 0
}

type Devices struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Device        []*Device              `protobuf:"bytes,1,rep,name=device,proto3" json:"device,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Devices) Reset() {
	*x = Devices{}
	mi := &file_adb_host_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Devices) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Devices) ProtoMessage() {}

func (x *Devices) ProtoReflect() protoreflect.Message {
	mi := &file_adb_host_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Devices.ProtoReflect.Descriptor instead.
func (*Devices) Descriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{1}
}

func (x *Devices) GetDevice() []*Device {
	if x != nil {
		return x.Device
	}
	return nil
}

type AdbServerStatus struct {
	state                  protoimpl.MessageState      `protogen:"open.v1"`
	UsbBackend             AdbServerStatus_UsbBackend  `protobuf:"varint,1,opt,name=usb_backend,json=usbBackend,proto3,enum=adb.proto.AdbServerStatus_UsbBackend" json:"usb_backend,omitempty"`
	UsbBackendForced       bool                        `protobuf:"varint,2,opt,name=usb_backend_forced,json=usbBackendForced,proto3" json:"usb_backend_forced,omitempty"`
	MdnsBackend            AdbServerStatus_MdnsBackend `protobuf:"varint,3,opt,name=mdns_backend,json=mdnsBackend,proto3,enum=adb.proto.AdbServerStatus_MdnsBackend" json:"mdns_backend,omitempty"`
	MdnsBackendForced      bool                        `protobuf:"varint,4,opt,name=mdns_backend_forced,json=mdnsBackendForced,proto3" json:"mdns_backend_forced,omitempty"`
	Version                string                      `protobuf:"bytes,5,opt,name=version,proto3" json:"version,omitempty"`
	Build                  string                      `protobuf:"bytes,6,opt,name=build,proto3" json:"build,omitempty"`
	ExecutableAbsolutePath string                      `protobuf:"bytes,7,opt,name=executable_absolute_path,json=executableAbsolutePath,proto3" json:"executable_absolute_path,omitempty"`
	LogAbsolutePath        string                      `protobuf:"bytes,8,opt,name=log_absolute_path,json=logAbsolutePath,proto3" json:"log_absolute_path,omitempty"`
	Os                     string                      `protobuf:"bytes,9,opt,name=os,proto3" json:"os,omitempty"`
	TraceLevel             *string                     `protobuf:"bytes,10,opt,name=trace_level,json=traceLevel,proto3,oneof" json:"trace_level,omitempty"`
	BurstMode              *bool                       `protobuf:"varint,11,opt,name=burst_mode,json=burstMode,proto3,oneof" json:"burst_mode,omitempty"`
	MdnsEnabled            *bool                       `protobuf:"varint,12,opt,name=mdns_enabled,json=mdnsEnabled,proto3,oneof" json:"mdns_enabled,omitempty"`
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *AdbServerStatus) Reset() {
	*x = AdbServerStatus{}
	mi := &file_adb_host_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdbServerStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdbServerStatus) ProtoMessage() {}

func (x *AdbServerStatus) ProtoReflect() protoreflect.Message {
	mi := &file_adb_host_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdbServerStatus.ProtoReflect.Descriptor instead.
func (*AdbServerStatus) Descriptor() ([]byte, []int) {
	return file_adb_host_proto_rawDescGZIP(), []int{2}
}

func (x *AdbServerStatus) GetUsbBackend() AdbServerStatus_UsbBackend {
	if x != nil {
		return x.UsbBackend
	}
	return AdbServerStatus_UNKNOWN_USB
}

func (x *AdbServerStatus) GetUsbBackendForced() bool {
	if x != nil {
		return x.UsbBackendForced
	}
	return false
}

func (x *AdbServerStatus) GetMdnsBackend() AdbServerStatus_MdnsBackend {
	if x != nil {
		return x.MdnsBackend
	}
	return AdbServerStatus_UNKNOWN_MDNS
}

func (x *AdbServerStatus) GetMdnsBackendForced() bool {
	if x != nil {
		return x.MdnsBackendForced
	}
	return false
}

func (x *AdbServerStatus) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *AdbServerStatus) GetBuild() string {
	if x != nil {
		return x.Build
	}
	return ""
}

func (x *AdbServerStatus) GetExecutableAbsolutePath() string {
	if x != nil {
		return x.ExecutableAbsolutePath
	}
	return ""
}

func (x *AdbServerStatus) GetLogAbsolutePath() string {
	if x != nil {
		return x.LogAbsolutePath
	}
	return ""
}

func (x *AdbServerStatus) GetOs() string {
	if x != nil {
		return x.Os
	}
	return ""
}

func (x *AdbServerStatus) GetTraceLevel() string {
	if x != nil && x.TraceLevel != nil {
		return *x.TraceLevel
	}
	return ""
}

func (x *AdbServerStatus) GetBurstMode() bool {
	if x != nil && x.BurstMode != nil {
		return *x.BurstMode
	}
	return false
}

func (x *AdbServerStatus) GetMdnsEnabled() bool {
	if x != nil && x.MdnsEnabled != nil {
		return *x.MdnsEnabled
	}
	return false
}

var File_adb_host_proto protoreflect.FileDescriptor

const file_adb_host_proto_rawDesc = "" +
	"\n" +
	"\x0eadb_host.proto\x12\tadb.proto\"\xea\x02\n" +
	"\x06Device\x12\x16\n" +
	"\x06serial\x18\x01 \x01(\tR\x06serial\x120\n" +
	"\x05state\x18\x02 \x01(\x0e2\x1a.adb.proto.ConnectionStateR\x05state\x12\x1f\n" +
	"\vbus_address\x18\x03 \x01(\tR\n" +
	"busAddress\x12\x18\n" +
	"\aproduct\x18\x04 \x01(\tR\aproduct\x12\x14\n" +
	"\x05model\x18\x05 \x01(\tR\x05model\x12\x16\n" +
	"\x06device\x18\x06 \x01(\tR\x06device\x12B\n" +
	"\x0fconnection_type\x18\a \x01(\x0e2\x19.adb.proto.ConnectionTypeR\x0econnectionType\x12)\n" +
	"\x10negotiated_speed\x18\b \x01(\x03R\x0fnegotiatedSpeed\x12\x1b\n" +
	"\tmax_speed\x18\t \x01(\x03R\bmaxSpeed\x12!\n" +
	"\ftransport_id\x18\n" +
	" \x01(\x03R\vtransportId\"4\n" +
	"\aDevices\x12)\n" +
	"\x06device\x18\x01 \x03(\v2\x11.adb.proto.DeviceR\x06device\"\xbf\x05\n" +
	"\x0fAdbServerStatus\x12F\n" +
	"\vusb_backend\x18\x01 \x01(\x0e2%.adb.proto.AdbServerStatus.UsbBackendR\n" +
	"usbBackend\x12,\n" +
	"\x12usb_backend_forced\x18\x02 \x01(\bR\x10usbBackendForced\x12I\n" +
	"\fmdns_backend\x18\x03 \x01(\x0e2&.adb.proto.AdbServerStatus.MdnsBackendR\vmdnsBackend\x12.\n" +
	"\x13mdns_backend_forced\x18\x04 \x01(\bR\x11mdnsBackendForced\x12\x18\n" +
	"\aversion\x18\x05 \x01(\tR\aversion\x12\x14\n" +
	"\x05build\x18\x06 \x01(\tR\x05build\x128\n" +
	"\x18executable_absolute_path\x18\a \x01(\tR\x16executableAbsolutePath\x12*\n" +
	"\x11log_absolute_path\x18\b \x01(\tR\x0flogAbsolutePath\x12\x0e\n" +
	"\x02os\x18\t \x01(\tR\x02os\x12$\n" +
	"\vtrace_level\x18\n" +
	" \x01(\tH\x00R\n" +
	"traceLevel\x88\x01\x01\x12\"\n" +
	"\n" +
	"burst_mode\x18\v \x01(\bH\x01R\tburstMode\x88\x01\x01\x12&\n" +
	"\fmdns_enabled\x18\f \x01(\bH\x02R\vmdnsEnabled\x88\x01\x01\"5\n" +
	"\n" +
	"UsbBackend\x12\x0f\n" +
	"\vUNKNOWN_USB\x10\x00\x12\n" +
	"\n" +
	"\x06NATIVE\x10\x01\x12\n" +
	"\n" +
	"\x06LIBUSB\x10\x02\"<\n" +
	"\vMdnsBackend\x12\x10\n" +
	"\fUNKNOWN_MDNS\x10\x00\x12\v\n" +
	"\aBONJOUR\x10\x01\x12\x0e\n" +
	"\n" +
	"OPENSCREEN\x10\x02B\x0e\n" +
	"\f_trace_levelB\r\n" +
	"\v_burst_modeB\x0f\n" +
	"\r_mdns_enabled*\xc8\x01\n" +
	"\x0fConnectionState\x12\a\n" +
	"\x03ANY\x10\x00\x12\x0e\n" +
	"\n" +
	"CONNECTING\x10\x01\x12\x0f\n" +
	"\vAUTHORIZING\x10\x02\x12\x10\n" +
	"\fUNAUTHORIZED\x10\x03\x12\x10\n" +
	"\fNOPERMISSION\x10\x04\x12\f\n" +
	"\bDETACHED\x10\x05\x12\v\n" +
	"\aOFFLINE\x10\x06\x12\x0e\n" +
	"\n" +
	"BOOTLOADER\x10\a\x12\n" +
	"\n" +
	"\x06DEVICE\x10\b\x12\b\n" +
	"\x04HOST\x10\t\x12\f\n" +
	"\bRECOVERY\x10\n" +
	"\x12\f\n" +
	"\bSIDELOAD\x10\v\x12\n" +
	"\n" +
	"\x06RESCUE\x10\f*2\n" +
	"\x0eConnectionType\x12\v\n" +
	"\aUNKNOWN\x10\x00\x12\a\n" +
	"\x03USB\x10\x01\x12\n" +
	"\n" +
	"\x06SOCKET\x10\x02B-\n" +
	"\x1dcom.android.server.adb.protosB\fDevicesProtob\x06proto3"

var (
	file_adb_host_proto_rawDescOnce sync.Once
	file_adb_host_proto_rawDescData []byte
)

func file_adb_host_proto_rawDescGZIP() []byte {
	file_adb_host_proto_rawDescOnce.Do(func() {
		file_adb_host_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_adb_host_proto_rawDesc), len(file_adb_host_proto_rawDesc)))
	})
	return file_adb_host_proto_rawDescData
}

var file_adb_host_proto_enumTypes = make([]protoimpl.EnumInfo, 4)
var file_adb_host_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_adb_host_proto_goTypes = []any{
	(ConnectionState)(0),             // 0: adb.proto.ConnectionState
	(ConnectionType)(0),              // 1: adb.proto.ConnectionType
	(AdbServerStatus_UsbBackend)(0),  // 2: adb.proto.AdbServerStatus.UsbBackend
	(AdbServerStatus_MdnsBackend)(0), // 3: adb.proto.AdbServerStatus.MdnsBackend
	(*Device)(nil),                   // 4: adb.proto.Device
	(*Devices)(nil),                  // 5: adb.proto.Devices
	(*AdbServerStatus)(nil),          // 6: adb.proto.AdbServerStatus
}
var file_adb_host_proto_depIdxs = []int32{
	0, // 0: adb.proto.Device.state:type_name -> adb.proto.ConnectionState
	1, // 1: adb.proto.Device.connection_type:type_name -> adb.proto.ConnectionType
	4, // 2: adb.proto.Devices.device:type_name -> adb.proto.Device
	2, // 3: adb.proto.AdbServerStatus.usb_backend:type_name -> adb.proto.AdbServerStatus.UsbBackend
	3, // 4: adb.proto.AdbServerStatus.mdns_backend:type_name -> adb.proto.AdbServerStatus.MdnsBackend
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_adb_host_proto_init() }
func file_adb_host_proto_init() {
	if File_adb_host_proto != nil {
		return
	}
	file_adb_host_proto_msgTypes[2].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_adb_host_proto_rawDesc), len(file_adb_host_proto_rawDesc)),
			NumEnums:      4,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_adb_host_proto_goTypes,
		DependencyIndexes: file_adb_host_proto_depIdxs,
		EnumInfos:         file_adb_host_proto_enumTypes,
		MessageInfos:      file_adb_host_proto_msgTypes,
	}.Build()
	File_adb_host_proto = out.File
	file_adb_host_proto_goTypes = nil
	file_adb_host_proto_depIdxs = nil
}
