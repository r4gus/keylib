const std = @import("std");
const cbor = @import("zbor");

const argon2 = std.crypto.pwhash.argon2;

pub const OuterHeader = struct {
    /// Changes made to the binary format should bump up
    /// the major version number.
    version_major: u16 = 1,
    /// Minor version number indicates minor patches.
    version_minor: u16 = 0,
    /// Encryption used for the data
    cipher: struct {
        type: Cipher,
        iv: ?[]const u8 = null,
    },
    /// Comperssion algorithm used for the data
    compression: Compression,
    /// Key derivation used to derive the secret from a password
    kdf: struct {
        type: Kdf,
        params: KdfParameters,
    },

    pub fn deinit(self: *const OuterHeader, a: std.mem.Allocator) void {
        if (self.cipher.iv) |iv| {
            a.free(iv);
        }
    }
};

pub const Cipher = enum {
    ChaCha20,

    pub fn iv(self: @This(), rand: std.rand.Random, a: std.mem.Allocator) ![]u8 {
        var mem = switch (self) {
            .ChaCha20 => try a.alloc(u8, 12),
        };

        rand.bytes(mem);
        return mem;
    }
};

pub const Kdf = enum {
    Argon2id,

    pub fn new(self: @This()) KdfParameters {
        switch (self) {
            .Argon2id => {
                var x = KdfParameters{
                    .Argon2id = .{
                        .S = undefined,
                        // recommendations by OWASP
                        .P = 1,
                        .M = 7168,
                        .I = 5,
                    },
                };
                return x;
            },
        }
    }
};

pub const KdfParameters = union(Kdf) {
    Argon2id: struct {
        /// Salt
        S: [32]u8,
        /// Parallelism
        P: u24,
        /// Memory usage in bytes
        M: u32,
        /// Iterations
        I: u32,
    },

    pub fn seed(self: *@This(), rand: std.rand.Random) void {
        switch (self.*) {
            .Argon2id => |*p| {
                rand.bytes(p.S[0..]);
            },
        }
    }

    pub fn derive(self: @This(), out: []u8, pw: []const u8, allocator: std.mem.Allocator) !void {
        switch (self) {
            .Argon2id => |p| {
                try argon2.kdf(allocator, out, pw, p.S[0..], .{ .t = p.I, .m = p.M, .p = p.P }, .argon2id);
            },
        }
    }
};

pub const Compression = enum {
    None,
    Gzip,
};

test "derive secret using argon2id" {
    //const allocator = std.testing.allocator;
    //const p = Kdf.Argon2id.new(std.crypto.random);
    //var out: [32]u8 = undefined;
    //try p.derive(out[0..], "password", allocator);

    //std.debug.print("{s}\nP={d}\nM={d}\nI={d}\n{s}\n", .{
    //    std.fmt.fmtSliceHexLower(p.Argon2id.S[0..]),
    //    p.Argon2id.P,
    //    p.Argon2id.M,
    //    p.Argon2id.I,
    //    std.fmt.fmtSliceHexLower(out[0..]),
    //});
}

test "header serialization test #1" {
    const allocator = std.testing.allocator;

    const h = OuterHeader{
        // 1.0
        .version_major = 1,
        .version_minor = 0,
        .cipher = .{
            .type = .ChaCha20,
            .iv = "\xc2\x90\x5c\x00\xf9\xc5\x27\x21\x6d\xa9\xc4\x3a",
        },
        .compression = .None,
        .kdf = .{
            .type = .Argon2id,
            .params = KdfParameters{ .Argon2id = .{
                .S = "\x90\xcb\x5e\x4d\x38\x0f\xa2\x8a\xe2\x80\x5d\x8f\xbb\xba\xd1\x27\xd4\x5b\xd4\x61\x49\x74\x2e\x8a\x88\x56\x87\xc2\x6f\xa8\x18\x30".*,
                .P = 8,
                .M = 0x40000000,
                .I = 2,
            } },
        },
    };

    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();
    try cbor.stringify(h, .{}, str.writer());
}

test "header deserialization test #1" {
    const allocator = std.testing.allocator;

    const di = try cbor.DataItem.new("\xa6\x6d\x76\x65\x72\x73\x69\x6f\x6e\x5f\x6d\x61\x6a\x6f\x72\x01\x6d\x76\x65\x72\x73\x69\x6f\x6e\x5f\x6d\x69\x6e\x6f\x72\x00\x66\x63\x69\x70\x68\x65\x72\xa2\x64\x74\x79\x70\x65\x68\x43\x68\x61\x43\x68\x61\x32\x30\x62\x69\x76\x4c\xc2\x90\x5c\x00\xf9\xc5\x27\x21\x6d\xa9\xc4\x3a\x6b\x63\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e\x64\x4e\x6f\x6e\x65\x64\x73\x65\x65\x64\x58\x20\x98\x40\xce\xf8\x3b\x1a\x39\x41\x14\xff\x5a\x91\xe0\xf8\x27\xc6\x40\x63\x4e\x5a\x64\x64\x90\x2a\xc1\xba\x9a\xea\xfb\xda\x28\x6f\x63\x6b\x64\x66\xa2\x64\x74\x79\x70\x65\x68\x41\x72\x67\x6f\x6e\x32\x69\x64\x66\x70\x61\x72\x61\x6d\x73\xa4\x61\x53\x58\x20\x90\xcb\x5e\x4d\x38\x0f\xa2\x8a\xe2\x80\x5d\x8f\xbb\xba\xd1\x27\xd4\x5b\xd4\x61\x49\x74\x2e\x8a\x88\x56\x87\xc2\x6f\xa8\x18\x30\x61\x50\x08\x61\x4d\x1a\x40\x00\x00\x00\x61\x49\x02");
    const h = try cbor.parse(OuterHeader, di, .{ .allocator = allocator });
    defer h.deinit(allocator);

    try std.testing.expectEqual(h.version_major, 1);
    try std.testing.expectEqual(h.version_minor, 0);
    try std.testing.expectEqual(Cipher.ChaCha20, h.cipher.type);
    try std.testing.expectEqualSlices(u8, "\xc2\x90\x5c\x00\xf9\xc5\x27\x21\x6d\xa9\xc4\x3a", h.cipher.iv.?);
    try std.testing.expectEqual(Compression.None, h.compression);
    try std.testing.expectEqual(Kdf.Argon2id, h.kdf.type);
    try std.testing.expectEqualSlices(u8, "\x90\xcb\x5e\x4d\x38\x0f\xa2\x8a\xe2\x80\x5d\x8f\xbb\xba\xd1\x27\xd4\x5b\xd4\x61\x49\x74\x2e\x8a\x88\x56\x87\xc2\x6f\xa8\x18\x30", h.kdf.params.Argon2id.S[0..]);
    try std.testing.expectEqual(h.kdf.params.Argon2id.P, 8);
    try std.testing.expectEqual(h.kdf.params.Argon2id.M, 0x40000000);
    try std.testing.expectEqual(h.kdf.params.Argon2id.I, 2);
}
