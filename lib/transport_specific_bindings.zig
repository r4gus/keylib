/// CTAP USB HID transport layer
pub const ctaphid = @import("transport_specific_bindings/ctaphid.zig");

test "transport specific bindings" {
    _ = ctaphid;
}
