const cbor = @import("zbor");

pub const ABS64B = cbor.ArrayBackedSlice(64, u8, .Byte);
pub const ABS64T = cbor.ArrayBackedSlice(64, u8, .Text);
pub const ABS128T = cbor.ArrayBackedSlice(128, u8, .Text);
