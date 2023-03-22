const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi/hidapi.h");
});

/// Copy a standard c string
///
/// This will return an utf-8 string
pub fn copy_c_string(allocator: std.mem.Allocator, s: [*c]u8) ![:0]u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    var s_copy: [:0]u8 = try allocator.allocSentinel(u8, i, 0);
    std.mem.copy(u8, s_copy, s[0..i]);
    return s_copy;
}

/// Copy a wchar_t string
///
/// This will return a utf-16 string
pub fn copy_wchar_t_string(allocator: std.mem.Allocator, s: [*c]hidapi.wchar_t) ![:0]u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    var s_copy: [:0]u8 = try allocator.allocSentinel(u8, i * 2, 0); // wchar_t is 16 bit unicode
    var j: usize = 0;
    var k: usize = 0;
    while (j < i) : (j += 1) {
        const wchar = s[j];
        s_copy[k] = @intCast(u8, wchar & 0xff);
        s_copy[k + 1] = @intCast(u8, wchar >> 8);
        k += 2;
    }
    return s_copy;
}
