//! This module provides functions for dealing with CTAP messages framed
//! for USB transport using the HID (Human Interface Device) protocol (CTAPHID).
//!
//! The communication between a client and the authenticator can be defined in
//! terms of transactions, which consist of a request message issued by a client,
//! followed by a response message.
//!
//! Each message consists of one or more packets with a maximum size s
//! (usually 64 Bytes for full speed usb). The first packet send is always
//! a initialization packet followed by zero or more continuation packets.
//! (see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure)

const std = @import("std");
const Allocator = std.mem.Allocator;

const command = @import("ctaphid/command.zig");
const Cmd = command.Cmd;
const CMD_LENGTH = command.CMD_LENGTH;

const misc = @import("ctaphid/misc.zig");
const Cid = misc.Cid;
const Nonce = misc.Nonce;
const CID_LENGTH = misc.CID_LENGTH;
const NONCE_LENGTH = misc.NONCE_LENGTH;
const BCNT_LENGTH = misc.BCNT_LENGTH;

const resp = @import("ctaphid/response.zig");
const CtapHidResponseIterator = resp.CtapHidResponseIterator;

pub const INIT_DATA_LENGTH: u16 = @sizeOf(InitResponse);

/// Supported error codes by the CTAPHID_ERROR response.
pub const ErrorCodes = enum(u8) {
    /// The command in the request is invalid.
    invalid_cmd = 0x01,
    /// The parameters in the request are invalid.
    invalid_par = 0x02,
    /// The length field (BCNT) is invalid for the request.
    invalid_len = 0x03,
    /// The sequence does not match the expected value.
    invalid_seq = 0x04,
    /// The message has timed out,
    msg_timeout = 0x05,
    /// The device is busy for the requesting channel.
    channel_busy = 0x06,
    /// Command requires channel lock.
    lock_required = 0x0a,
    /// CID is not valid.
    invalid_channel = 0x0b,
    /// Unspecified error.
    other = 0x7f,
};

pub const channels = struct {
    // CID 0 and ffffffff are reserved for broadcast communication.
    var idctr: u32 = 0;

    /// Allocate a new channel Id (CID) for communication with a client.
    pub fn allocateChannelId() u32 {
        idctr += 1;
        return idctr;
    }

    /// Check if the given CID represents a broadcast channel.
    pub fn isBroadcast(cid: Cid) bool {
        return cid == 0 or cid == 0xffffffff;
    }

    /// Check if the given cid has been allocated.
    pub fn isValid(cid: Cid) bool {
        return 0 < cid and cid <= idctr;
    }
};

//--------------------------------------------------------------------+
// INIT
//--------------------------------------------------------------------+

/// The response data of a INIT request.
pub const InitResponse = packed struct {
    /// The nonce send with the client request.
    nonce: Nonce,
    /// The allocated 4 byte channel id.
    cid: Cid,
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
    reserved1: bool,
    /// If set to 1, authenticator implements CTAPHID_CBOR function.
    cbor: bool,
    /// If set to 1, authenticator DOES NOT implement CTAPHID_MSG function.
    nmsg: bool,
    /// Reserved for future use (must be set to 0).
    reserved2: bool,
    /// Reserved for future use (must be set to 0).
    reserved3: bool,
    /// Reserved for future use (must be set to 0).
    reserved4: bool,
    /// Reserved for future use (must be set to 0).
    reserved5: bool,

    pub fn new(nonce: Nonce, cid: Cid, wink: bool, cbor: bool, nmsg: bool) @This() {
        return @This(){
            .nonce = nonce,
            .cid = cid,
            .version_identifier = 2,
            .major_device_version_number = 1,
            .minor_device_version_number = 0,
            .build_device_version_number = 0,
            .wink = wink,
            .reserved1 = false,
            .cbor = cbor,
            .nmsg = nmsg,
            .reserved2 = false,
            .reserved3 = false,
            .reserved4 = false,
            .reserved5 = false,
        };
    }

    pub fn serialize(self: *const @This(), slice: []u8) void {
        misc.intToSlice(slice[0..NONCE_LENGTH], self.nonce);
        misc.intToSlice(slice[COFF .. COFF + CID_LENGTH], self.cid);
        slice[VIOFF] = self.version_identifier;
        slice[MJDOFF] = self.major_device_version_number;
        slice[MIDOFF] = self.minor_device_version_number;
        slice[BDOFF] = self.build_device_version_number;
        slice[FOFF] = (@intCast(u8, @boolToInt(self.nmsg)) << 3) + (@intCast(u8, @boolToInt(self.cbor)) << 2) + (@intCast(u8, @boolToInt(self.wink)));
    }

    const NOFF: usize = 0;
    const COFF: usize = @sizeOf(Nonce);
    const VIOFF: usize = COFF + @sizeOf(Cid);
    const MJDOFF: usize = VIOFF + 1;
    const MIDOFF: usize = MJDOFF + 1;
    const BDOFF: usize = MIDOFF + 1;
    const FOFF: usize = BDOFF + 1;

    pub const SIZE: usize = FOFF + 1;
};

//--------------------------------------------------------------------+
// Response Handler
//--------------------------------------------------------------------+

// TODO: assume that the allocator will always provide enough memory.
pub fn handle(allocator: Allocator, packet: []const u8, auth: anytype) ?CtapHidResponseIterator {
    const S = struct {
        // Authenticator is currently busy handling a request with the given
        // Cid. `null` means not busy.
        var busy: ?Cid = null;
        // Command to be executed.
        var cmd: ?Cmd = null;
        // The ammount of expected data bytes (max is: 64 - 7 + 128 * (64 - 5) = 7609).
        var bcnt_total: u16 = 0;
        // Data bytes already received.
        var bcnt: u16 = 0;
        // Last sequence number (continuation packet).
        var seq: ?u8 = 0;
        // Data buffer.
        // All clients (CIDs) share the same buffer, i.e. only one request
        // can be handled at a time.
        var data: [7609]u8 = undefined;

        pub fn @"error"(e: ErrorCodes) CtapHidResponseIterator {
            const es = switch (e) {
                .invalid_cmd => "\x01",
                .invalid_par => "\x02",
                .invalid_len => "\x03",
                .invalid_seq => "\x04",
                .msg_timeout => "\x05",
                .channel_busy => "\x06",
                .lock_required => "\x0a",
                .invalid_channel => "\x0b",
                else => "\x7f",
            };

            const response = resp.iterator(if (busy) |c| c else 0xffffffff, Cmd.err, es);

            busy = null;
            cmd = null;
            bcnt_total = 0;
            bcnt = 0;
            seq = 0;

            return response;
        }
    };

    if (S.busy == null) { // initialization packet
        if (packet.len < 7) {
            // TODO: error packet ist too short
        } else if (packet[4] & 0x80 == 0) {
            // TODO: error, expected initialization packet but found continuation packet
        }

        // TODO: handle error bit 7 of CMD not being set.
        S.busy = misc.sliceToInt(Cid, packet[0..4]);
        S.cmd = @intToEnum(Cmd, packet[4] & 0x7f);
        S.bcnt_total = misc.sliceToInt(u16, packet[5..7]);

        const l = packet.len - 7;
        std.mem.copy(u8, S.data[0..l], packet[7..]);
        S.bcnt = @intCast(u16, l);
    } else { // continuation packet
        if (packet.len < 5) {
            // TODO: error packet ist too short
        }

        if (misc.sliceToInt(Cid, packet[0..4]) != S.busy.?) {
            // TODO: error, cid's don't match
            // tell client that the authenticator is busy!
        } else if (packet[4] & 0x80 != 0) {
            // TODO: error, expected continuation packet but found initialization packet
        } else if ((S.seq == null and packet[4] > 0) or (S.seq != null and packet[4] != S.seq.? + 1)) {
            // TODO: unexpected sequence number
        }

        S.seq = packet[4];
        const l = packet.len - 5;
        std.mem.copy(u8, S.data[S.bcnt .. S.bcnt + l], packet[5..]);
        S.bcnt += @intCast(u16, l);
    }

    if (S.bcnt >= S.bcnt_total and S.busy != null and S.cmd != null) {
        defer reset(&S);

        switch (S.cmd.?) {
            .init => {},
            else => {
                if (!channels.isValid(S.busy.?)) {
                    //return S.@"error"(ErrorCodes.invalid_channel); //<---- BUG TODO
                }
            },
        }

        switch (S.cmd.?) {
            .init => {
                const ir = InitResponse.new(misc.sliceToInt(Nonce, S.data[0..8]), 0xcafebabe, false, true, false);
                var data = allocator.alloc(u8, InitResponse.SIZE) catch {
                    reset(&S);
                    return null;
                };
                ir.serialize(data[0..]);
                var response = resp.iterator(S.busy.?, S.cmd.?, data);

                return response;
            },
            .cbor => {
                var data = auth.handle(allocator, S.data[0..S.bcnt]) catch {
                    reset(&S);
                    return null;
                };

                var response = resp.iterator(S.busy.?, S.cmd.?, data);

                return response;
            },
            .ping => {
                var response = resp.iterator(S.busy.?, S.cmd.?, S.data[0..S.bcnt]);

                return response;
            },
            .cancel => {
                return null;
            },
            else => {
                return S.@"error"(ErrorCodes.invalid_cmd);
            },
        }
    }

    return null;
}

inline fn reset(s: anytype) void {
    s.*.busy = null;
    s.*.cmd = null;
    s.*.bcnt_total = 0;
    s.*.bcnt = 0;
    s.*.seq = null;
}

test "ctaphid test" {
    _ = command;
    _ = misc;
    _ = resp;
}
