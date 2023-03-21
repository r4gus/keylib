/// Transport specific bindings
pub const transport_specific_bindings = @import("transport_specific_bindings.zig");

/// Resources that must be provided by the platform
pub const Resources = @import("Resources.zig");

/// FIDO2 Authenticator
pub const Authenticator = @import("Authenticator.zig");

/// CTAP2 data types
pub const data = @import("data.zig");

const tests = @import("tests.zig");

test "main" {
    _ = transport_specific_bindings;
    _ = Resources;
    _ = Authenticator;
    _ = data;
    _ = tests;
}
