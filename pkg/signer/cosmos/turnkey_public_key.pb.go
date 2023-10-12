// buf:lint:ignore PACKAGE_VERSION_SUFFIX

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: signer/cosmos/turnkey_public_key.proto

package cosmos

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TurnkeyPublicKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id             string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	OrganizationId string `protobuf:"bytes,2,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	PublicKey      string `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	KeyType        string `protobuf:"bytes,4,opt,name=key_type,json=keyType,proto3" json:"key_type,omitempty"`
}

func (x *TurnkeyPublicKey) Reset() {
	*x = TurnkeyPublicKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signer_cosmos_turnkey_public_key_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TurnkeyPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TurnkeyPublicKey) ProtoMessage() {}

func (x *TurnkeyPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_signer_cosmos_turnkey_public_key_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TurnkeyPublicKey.ProtoReflect.Descriptor instead.
func (*TurnkeyPublicKey) Descriptor() ([]byte, []int) {
	return file_signer_cosmos_turnkey_public_key_proto_rawDescGZIP(), []int{0}
}

func (x *TurnkeyPublicKey) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *TurnkeyPublicKey) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *TurnkeyPublicKey) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

func (x *TurnkeyPublicKey) GetKeyType() string {
	if x != nil {
		return x.KeyType
	}
	return ""
}

var File_signer_cosmos_turnkey_public_key_proto protoreflect.FileDescriptor

var file_signer_cosmos_turnkey_public_key_proto_rawDesc = []byte{
	0x0a, 0x26, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f,
	0x74, 0x75, 0x72, 0x6e, 0x6b, 0x65, 0x79, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72,
	0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x22, 0x85, 0x01, 0x0a, 0x10, 0x54, 0x75, 0x72, 0x6e,
	0x6b, 0x65, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x27, 0x0a, 0x0f,
	0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x6b, 0x65, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x42,
	0x34, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x6b,
	0x68, 0x71, 0x2f, 0x67, 0x6f, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x73,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x2f, 0x63,
	0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_signer_cosmos_turnkey_public_key_proto_rawDescOnce sync.Once
	file_signer_cosmos_turnkey_public_key_proto_rawDescData = file_signer_cosmos_turnkey_public_key_proto_rawDesc
)

func file_signer_cosmos_turnkey_public_key_proto_rawDescGZIP() []byte {
	file_signer_cosmos_turnkey_public_key_proto_rawDescOnce.Do(func() {
		file_signer_cosmos_turnkey_public_key_proto_rawDescData = protoimpl.X.CompressGZIP(file_signer_cosmos_turnkey_public_key_proto_rawDescData)
	})
	return file_signer_cosmos_turnkey_public_key_proto_rawDescData
}

var file_signer_cosmos_turnkey_public_key_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_signer_cosmos_turnkey_public_key_proto_goTypes = []interface{}{
	(*TurnkeyPublicKey)(nil), // 0: signer.cosmos.TurnkeyPublicKey
}
var file_signer_cosmos_turnkey_public_key_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_signer_cosmos_turnkey_public_key_proto_init() }
func file_signer_cosmos_turnkey_public_key_proto_init() {
	if File_signer_cosmos_turnkey_public_key_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_signer_cosmos_turnkey_public_key_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TurnkeyPublicKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_signer_cosmos_turnkey_public_key_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_signer_cosmos_turnkey_public_key_proto_goTypes,
		DependencyIndexes: file_signer_cosmos_turnkey_public_key_proto_depIdxs,
		MessageInfos:      file_signer_cosmos_turnkey_public_key_proto_msgTypes,
	}.Build()
	File_signer_cosmos_turnkey_public_key_proto = out.File
	file_signer_cosmos_turnkey_public_key_proto_rawDesc = nil
	file_signer_cosmos_turnkey_public_key_proto_goTypes = nil
	file_signer_cosmos_turnkey_public_key_proto_depIdxs = nil
}
