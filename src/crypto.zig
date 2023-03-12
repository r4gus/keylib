/// Elliptic curve diffie-hellman
pub const ecdh = @import("crypto/ecdh.zig");

/// Algorithms used for signing
pub const algorithms = @import("crypto/algorithms.zig");

/// Master secret module
pub const ms = @import("crypto/master_secret.zig");

/// Context module
pub const context = @import("crypto/context.zig");

pub const pin = @import("crypto/pin.zig");

test "crypto tests" {
    _ = algorithms;
    _ = ms;
    _ = context;
    _ = pin;
}
