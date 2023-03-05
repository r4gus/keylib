const std = @import("std");
const ctaphid = @import("../ctaphid.zig");
const misc = @import("misc.zig");
const command = @import("command.zig");

/// Size of a USB full speed packet
pub const PACKET_SIZE = 64;
/// Size of the initialization packet header
pub const IP_HEADER_SIZE = 7;
/// Size of the continuation packet header
pub const CP_HEADER_SIZE = 5;
/// Data size of a initialization packet
pub const IP_DATA_SIZE = PACKET_SIZE - IP_HEADER_SIZE;
/// Data size of a continuation packet
pub const CP_DATA_SIZE = PACKET_SIZE - CP_HEADER_SIZE;

// Offset of the CMD header field
const CMD_OFFSET = misc.CID_LENGTH;
// Offset of the BCNT header field
const BCNT_OFFSET = CMD_OFFSET + command.CMD_LENGTH;
// Offset of the data section (initialization packet)
const IP_DATA_OFFSET = BCNT_OFFSET + misc.BCNT_LENGTH;
// Offset of the SEQ header field
const SEQ_OFFSET = misc.CID_LENGTH;
// Offset of the data section (continuation packet)
const CP_DATA_OFFSET = SEQ_OFFSET + misc.SEQ_LENGTH;

// Command identifier; Bit 7 of the CMD header field must
// be set to mark a initialization packet.
const COMMAND_ID = 0x80;

/// Iterator for a CTAPHID response.
///
/// The iterator acts as a view into a data slice (the bytes to be sent to the client).
///
/// The first time `next()` is called, the iterator will return a `u8` slice of size `PACKET_SIZE` (64 Bytes, i.e. USB full speed) which contains a initialization packet, i.e. header plus the first data bytes (`PACKET_SIZE`-7). Every continuous call to `next()` will return a continuation packet until all data bytes have been encoded.
pub const CtapHidResponseIterator = struct {
    cntr: usize = 0,
    seq: misc.Seq = 0,
    buffer: [PACKET_SIZE]u8 = undefined,
    data: []const u8 = &.{},
    cid: misc.Cid,
    cmd: command.Cmd,
    raw: [2048]u8 = undefined,

    pub fn new(
        cid: misc.Cid,
        cmd: command.Cmd,
    ) CtapHidResponseIterator {
        return .{
            .cid = cid,
            .cmd = cmd,
        };
    }

    /// Get the next data packet.
    ///
    /// Returns `null` if all data bytes have been processed.
    pub fn next(self: *@This()) ?[]const u8 {
        if (self.cntr < self.data.len or (self.data.len == 0 and self.cntr == 0)) {
            // Zero the whole buffer
            std.mem.set(u8, self.buffer[0..], 0);

            var len: usize = undefined;
            var off: usize = undefined;
            if (self.cntr == 0) { // initialization packet
                len = if (self.data.len <= IP_DATA_SIZE) self.data.len else IP_DATA_SIZE;
                off = IP_DATA_OFFSET;

                misc.intToSlice(self.buffer[0..misc.CID_LENGTH], self.cid);
                self.buffer[CMD_OFFSET] = @enumToInt(self.cmd) | COMMAND_ID;
                misc.intToSlice(self.buffer[BCNT_OFFSET .. BCNT_OFFSET + misc.BCNT_LENGTH], @intCast(misc.Bcnt, self.data.len));
            } else {
                len = if (self.data.len - self.cntr <= CP_DATA_SIZE) self.data.len - self.cntr else CP_DATA_SIZE;
                off = CP_DATA_OFFSET;

                misc.intToSlice(self.buffer[0..misc.CID_LENGTH], self.cid);
                self.buffer[SEQ_OFFSET] = self.seq;

                self.seq += 1;
            }

            std.mem.copy(u8, self.buffer[off..], self.data[self.cntr .. self.cntr + len]);
            self.cntr += len;

            if (self.data.len == 0) {
                // special case: data slice is empty.
                // prevents this block from executing twice.
                self.cntr = 1;
            }

            return self.buffer[0..];
        } else {
            return null;
        }
    }
};

/// Create a new `CtapHidResponseIterator`.
pub fn iterator(
    cid: misc.Cid,
    cmd: command.Cmd,
    data: []const u8,
) CtapHidResponseIterator {
    return CtapHidResponseIterator{
        .cntr = 0,
        .seq = 0,
        .buffer = undefined,
        .data = data,
        .cid = cid,
        .cmd = cmd,
    };
}

test "Response Iterator 1" {
    const allocator = std.testing.allocator;
    var mem = try allocator.alloc(u8, 57);
    defer allocator.free(mem);

    std.mem.set(u8, mem[0..], 'a');

    var iter = iterator(0x11223344, command.Cmd.init, mem);

    const r1 = iter.next();
    try std.testing.expectEqualSlices(u8, "\x11\x22\x33\x44\x86\x00\x39aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", r1.?);

    try std.testing.expectEqual(iter.next(), null);
    try std.testing.expectEqual(iter.next(), null);
}

test "Response Iterator 2" {
    const allocator = std.testing.allocator;
    var mem = try allocator.alloc(u8, 17);
    defer allocator.free(mem);

    std.mem.set(u8, mem[0..], 'a');

    var iter = iterator(0x11223344, command.Cmd.init, mem);

    const r1 = iter.next();
    try std.testing.expectEqualSlices(u8, "\x11\x22\x33\x44\x86\x00\x11aaaaaaaaaaaaaaaaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", r1.?);

    try std.testing.expectEqual(iter.next(), null);
}

test "Response Iterator 3" {
    const allocator = std.testing.allocator;
    var mem = try allocator.alloc(u8, 74);
    defer allocator.free(mem);

    std.mem.set(u8, mem[0..57], 'a');
    std.mem.set(u8, mem[57..74], 'b');

    var iter = iterator(0xcafebabe, command.Cmd.cbor, mem);

    const r1 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x90\x00\x4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", r1.?);

    const r2 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x00bbbbbbbbbbbbbbbbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", r2.?);

    try std.testing.expectEqual(iter.next(), null);
}

test "Response Iterator 4" {
    const allocator = std.testing.allocator;
    var mem = try allocator.alloc(u8, 128);
    defer allocator.free(mem);

    std.mem.set(u8, mem[0..57], 'a');
    std.mem.set(u8, mem[57..116], 'b');
    std.mem.set(u8, mem[116..128], 'c');

    var iter = iterator(0xcafebabe, command.Cmd.cbor, mem);

    const r1 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x90\x00\x80aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", r1.?);

    const r2 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x00bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", r2.?);

    const r3 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x01cccccccccccc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", r3.?);

    try std.testing.expectEqual(iter.next(), null);
}

test "Response Iterator 5" {
    var iter = iterator(0xcafebabe, command.Cmd.cbor, &.{});

    const r1 = iter.next();
    try std.testing.expectEqualSlices(u8, "\xca\xfe\xba\xbe\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", r1.?);

    try std.testing.expectEqual(iter.next(), null);
    try std.testing.expectEqual(iter.next(), null);
    try std.testing.expectEqual(iter.next(), null);
}
