const std = @import("std");
const cbor = @import("zbor");

alg: cbor.cose.Algorithm,
type: [:0]const u8,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.type);
}
