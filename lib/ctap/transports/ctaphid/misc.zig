pub const Cid = u32;
pub const Nonce = u64;
pub const Bcnt = u16;
pub const Seq = u8;
pub const CID_LENGTH = @sizeOf(Cid);
pub const NONCE_LENGTH = @sizeOf(Nonce);
pub const BCNT_LENGTH = @sizeOf(Bcnt);
pub const SEQ_LENGTH = @sizeOf(Seq);

/// Convert a slice into an integer of the given type T
/// (big endian, i.e. network byte order).
///
/// IMPORTANT!: There are no checks that slice fits in T.
pub fn sliceToInt(comptime T: type, slice: []const u8) T {
    var res: T = 0;
    var i: usize = 0;
    while (i < @sizeOf(T)) : (i += 1) {
        res += @as(T, @intCast(slice[i]));

        if (i < @sizeOf(T) - 1) {
            res <<= 8;
        }
    }
    return res;
}

/// Convert an integer into a slice
/// (big endian, i.e. network byte order).
///
/// IMPORTANT!: There are no checks that T fits into the slice.
pub fn intToSlice(slice: []u8, i: anytype) void {
    // big endian
    var x = i;
    const SIZE: usize = @sizeOf(@TypeOf(i));

    var j: usize = 0;
    while (j < SIZE) : (j += 1) {
        slice[SIZE - 1 - j] = @as(u8, @intCast(x & 0xff));
        x >>= 8;
    }
}
