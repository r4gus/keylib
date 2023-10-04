const std = @import("std");
const fido = @import("../../main.zig");

/// Number of pin retries left
pinRetries: u8 = 8,
/// Number of uv retries left
uvRetries: u8 = 8,
/// Pin has to be changed
force_pin_change: bool = false,
/// The minimum pin length
min_pin_length: u8 = 4,
/// Enforce user verification
always_uv: bool = false,
/// Pin with a max length of 63 bytes
pin: ?[63]u8 = null,
/// Gloabl credential usage counter
usage_count: u64 = 0,
