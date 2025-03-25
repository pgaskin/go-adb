// Package adbppb contains adb protobuf definitions.
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/proto/;drc=9f298fb1f3317371b49439efb20a598b3a881bf3
package adbpb

//go:generate go run github.com/bufbuild/buf/cmd/buf@v1.50.1 generate --template {"version":"v2","plugins":[{"local":["go","tool","protoc-gen-go"],"out":".","opt":["paths=source_relative","Madb_host.proto=./adbpb","Madb_known_hosts.proto=./adbpb","Mapp_processes.proto=./adbpb","Mkey_type.proto=./adbpb","Mpairing.proto=./adbpb"]}]}
