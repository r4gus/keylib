const std = @import("std");
const cbor = @import("zbor");

pub const ecdsa = @import("ecdsa.zig"); // copy from std lib without automatic call to rng.
const EcdsaP256Sha256 = ecdsa.EcdsaP256Sha256;
pub const ecdh = @import("ecdh.zig");

test "crypto test" {
    _ = ecdh;
}
