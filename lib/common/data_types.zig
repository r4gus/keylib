const cbor = @import("zbor");
const fido = @import("../main.zig");

const AuthenticatorTransports = fido.common.AuthenticatorTransports;

pub const ABS32B = cbor.ArrayBackedSlice(32, u8, .Byte);
pub const ABS48B = cbor.ArrayBackedSlice(48, u8, .Byte);
pub const ABS64B = cbor.ArrayBackedSlice(64, u8, .Byte);
pub const ABS256B = cbor.ArrayBackedSlice(256, u8, .Byte);
pub const ABS512B = cbor.ArrayBackedSlice(512, u8, .Byte);

pub const ABS64T = cbor.ArrayBackedSlice(64, u8, .Text);
pub const ABS128T = cbor.ArrayBackedSlice(128, u8, .Text);

// Currently there are 6 different transports defined (usb, nfc, ble, smart-card, hybrid, and internal)
pub const ABSAuthenticatorTransports = cbor.ArrayBackedSlice(6, AuthenticatorTransports, .Other);
