package adbproto

// Feature is an optional feature supported by the device.
type Feature string

// Features as of version 41 (2025-03-25).
//
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/transport.cpp;l=81-105;drc=2d3e62c2af54a3e8f8803ea10492e63b8dfe709f
const (
	FeatureShell2                    = "shell_v2"
	FeatureCmd                       = "cmd"
	FeatureStat2                     = "stat_v2"
	FeatureLs2                       = "ls_v2"
	FeatureLibusb                    = "libusb"
	FeaturePushSync                  = "push_sync"
	FeatureApex                      = "apex"
	FeatureFixedPushMkdir            = "fixed_push_mkdir"
	FeatureAbb                       = "abb"
	FeatureFixedPushSymlinkTimestamp = "fixed_push_symlink_timestamp"
	FeatureAbbExec                   = "abb_exec"
	FeatureRemountShell              = "remount_shell"
	FeatureTrackApp                  = "track_app"
	FeatureSendRecv2                 = "sendrecv_v2"
	FeatureSendRecv2Brotli           = "sendrecv_v2_brotli"
	FeatureSendRecv2LZ4              = "sendrecv_v2_lz4"
	FeatureSendRecv2Zstd             = "sendrecv_v2_zstd"
	FeatureSendRecv2DryRunSend       = "sendrecv_v2_dry_run_send"
	FeatureDelayedAck                = "delayed_ack"
	FeatureOpenscreenMdns            = "openscreen_mdns"
	FeatureDeviceTrackerProtoFormat  = "devicetracker_proto_format"
	FeatureDevRaw                    = "devraw"
	FeatureAppInfo                   = "app_info"      // Add information to track-app (package name, ...)
	FeatureServerStatus              = "server_status" // Ability to output server status
)
