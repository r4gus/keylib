/// Transport specific bindings
pub const transport_specific_bindings = @import("transport_specific_bindings.zig");
/// CTAP2 data types
pub const data = @import("data.zig");

test "main" {
    _ = transport_specific_bindings;
    _ = data;
}
