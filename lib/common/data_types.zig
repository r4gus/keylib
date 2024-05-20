const cbor = @import("zbor");
const fido = @import("../main.zig");

const AuthenticatorTransports = fido.common.AuthenticatorTransports;

pub const ABS64B = cbor.ArrayBackedSlice(64, u8, .Byte);
pub const ABS64T = cbor.ArrayBackedSlice(64, u8, .Text);
pub const ABS128T = cbor.ArrayBackedSlice(128, u8, .Text);
// Currently there are 6 different transports defined (usb, nfc, ble, smart-card, hybrid, and internal)
pub const ABSAuthenticatorTransports = cbor.ArrayBackedSlice(6, AuthenticatorTransports, .Other);
