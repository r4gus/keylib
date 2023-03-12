const Sha256 = @import("std").crypto.hash.sha2.Sha256;

pub fn pin_hash(pin: []const u8) [16]u8 {
    var ph: [32]u8 = undefined;
    Sha256.hash(pin, &ph, .{});
    return ph[0..16].*;
}
