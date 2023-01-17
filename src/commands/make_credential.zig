const std = @import("std");
const cbor = @import("zbor");
const dobj = @import("../dobj.zig");

const Allocator = std.mem.Allocator;

pub const CredParam = struct {
    alg: cbor.cose.Algorithm,
    type: []const u8,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        allocator.free(self.type);
    }
};

pub const MakeCredentialParam = struct {
    /// clientDataHash: Hash of the ClientData contextual binding
    @"1": []const u8,
    /// rp: PublicKeyCredentialRpEntity
    ///
    /// id: valid domain string identifying the Relying Party
    /// name: user friendly name
    @"2": dobj.RelyingParty,
    /// user: PublicKeyCredentialUserEntity
    @"3": dobj.User,
    /// pubKeyCredParams: A sequence of CBOR maps
    @"4": []const CredParam,
    /// excludeList: A sequence of PublicKeyCredentialDescriptor structures.
    /// The authenticator returns an error if the authenticator already contains
    /// one of the credentials enumerated in this sequence.
    @"5": ?[]const dobj.PublicKeyCredentialDescriptor,
    // TODO: add remaining fields (extensions 0x6)
    /// authenticator options: Parameters to influence authenticator operation.
    @"7": ?dobj.AuthenticatorOptions,
    /// pinAuth: First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken
    /// which platform got from the authenticator: HMAC-SHA-256(pinToken, clientDataHash).
    @"8": ?[16]u8,
    /// pinProtocol: PIN protocol version chosen by the client.
    @"9": ?u8,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        allocator.free(self.@"1");
        allocator.free(self.@"2".id);
        if (self.@"2".name) |name| {
            allocator.free(name);
        }
        allocator.free(self.@"3".id);
        if (self.@"3".name) |name| {
            allocator.free(name);
        }
        if (self.@"3".displayName) |name| {
            allocator.free(name);
        }

        for (self.@"4") |cp| {
            cp.deinit(allocator);
        }
        allocator.free(self.@"4");

        if (self.@"5") |excludes| {
            for (excludes) |pkcd| {
                pkcd.deinit(allocator);
            }
            allocator.free(excludes);
        }
    }
};

test "cred params" {
    const allocator = std.testing.allocator;

    const payload = "\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const cred_param = try cbor.parse(CredParam, try cbor.DataItem.new(payload), .{ .allocator = allocator });
    defer cred_param.deinit(allocator);

    try std.testing.expectEqual(cred_param.alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqualSlices(u8, "public-key", cred_param.type);
}

test "make credential" {
    const allocator = std.testing.allocator;

    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const di = try cbor.DataItem.new(payload);

    const mcp = try cbor.parse(MakeCredentialParam, di, .{ .allocator = allocator });
    defer mcp.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c", mcp.@"1");
    try std.testing.expectEqualSlices(u8, "localhost", mcp.@"2".id);
    try std.testing.expectEqualSlices(u8, "sweet home localhost", mcp.@"2".name.?);
    try std.testing.expectEqualSlices(u8, "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49", mcp.@"3".id);
    try std.testing.expectEqualSlices(u8, "john smith", mcp.@"3".name.?);
    try std.testing.expectEqualSlices(u8, "jsmith", mcp.@"3".displayName.?);
    try std.testing.expectEqual(mcp.@"4"[0].alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqualSlices(u8, "public-key", mcp.@"4"[0].type);
}
