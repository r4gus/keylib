//! CTAPHID commands

const std = @import("std");

const fido = @import("../../main.zig");
const CtapHidMessageIterator = fido.transport_specific_bindings.ctaphid.CtapHidMessageIterator;
const Cmd = fido.transport_specific_bindings.ctaphid.Cmd;
const Authenticator = fido.client.device.Authenticator;

const sliceToInt = fido.transport_specific_bindings.ctaphid.misc.sliceToInt;

/// Device response of an init request
pub const InitResponse = packed struct {
    /// The nonce send with the client request.
    nonce: u64,
    /// The allocated 4 byte channel id.
    cid: u32,
    /// CTAPHID protocol version is 2.
    version_identifier: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    major_device_version_number: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    minor_device_version_number: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    build_device_version_number: u8,
    /// If set to 1, authenticator implements CTAPHID_WINK function.
    wink: bool,
    /// Reserved for future use (must be set to 0).
    reserved1: bool = false,
    /// If set to 1, authenticator implements CTAPHID_CBOR function.
    cbor: bool,
    /// If set to 1, authenticator DOES NOT implement CTAPHID_MSG function.
    nmsg: bool,
    /// Reserved for future use (must be set to 0).
    reserved2: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved3: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved4: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved5: bool = false,

    pub fn from_slice(s: []const u8) !@This() {
        if (s.len < 17) return error.InsufiicientData;

        return .{
            .nonce = sliceToInt(u64, s[0..8]),
            .cid = sliceToInt(u32, s[8..12]),
            .version_identifier = s[12],
            .major_device_version_number = s[13],
            .minor_device_version_number = s[14],
            .build_device_version_number = s[15],
            .wink = if (s[16] & 0x01 != 0) true else false,
            .cbor = if (s[16] & 0x04 != 0) true else false,
            .nmsg = if (s[16] & 0x08 != 0) true else false,
        };
    }
};

/// Initialize/ reset the connection to a device using a logical channel
///
/// This command has two functions:
///
/// 1. If sent on the broadcast CID (0xffffffff), it requests the device to allocate
/// a unique 32-bit channel identifier (CID) that can be used by the requesting
/// application during its lifetime.
///
/// 2. If sent on an allocated CID, it synchronizes a channel, discarding the
/// current transaction, buffers and state as quickly as possible.
pub fn ctaphid_init(auth: *Authenticator, cid: u32, allocator: std.mem.Allocator) !InitResponse {
    var msg = CtapHidMessageIterator.new(cid, Cmd.init);
    msg.data = "\x00\x01\x02\x03\x00\x01\x02\x03";

    try auth.ctaphid_write(&msg);
    const resp = try auth.ctaphid_read(allocator);
    defer allocator.free(resp);
    //std.debug.print("resp: {s}\n", .{std.fmt.fmtSliceHexLower(resp)});

    return try InitResponse.from_slice(resp);
}
