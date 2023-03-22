# fido2 library

![GitHub](https://img.shields.io/github/license/r4gus/ztap?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/r4gus/fido2/main.yml?style=flat-square)

> _Warning_: NOT PRODUCTION READY!

<details>
<summary>## FIDO2 authenticator support</summary>

### Getting started

The following steps are required to get started:

1. Add this repository to your project (make sure you call the `pull-deps.sh` script to fetch the required cbor library)
2. Implement a basic application that acts as a raw usb hid device
3. Define the following functions (take a look at the example [here](https://github.com/r4gus/candy-stick-nrf/blob/master/src/auth_descriptor.zig)):
  - `pub fn rand() u32` - Get a 32 bit (true) random number
  - `pub fn millis() u32` - The time in milliseconds since startup (or something similar)
  - `pub fn load(allocator: std.mem.Allocator) fido.Resources.LoadError![]u8` - Load data from memory (the first four bytes encode the data length and MUST NOT be returned)
  - `pub fn store(data: []const u8) void` - Store the given data to memory (the first four bytes encode the length)
  - `pub fn request_permission(user: ?*const fido.data.User, rp: ?*const fido.data.RelyingParty) bool` - Request permission from the user (e.g., button press)
4. On startup call `fido.Authenticator.new_default` to instantiate an authenticator
```zig
// call this on start up
auth = fido.Authenticator.new_default(
    [_]u8{
        ...      
    },                                                                          
    .{                          
        .rand = Impl.rand,
        .millis = Impl.millis,
        .load = Impl.load,     
        .store = Impl.store,
        .request_permission = Impl.requestPermission,
    },
);
```
6. On receiving a usb packet call `fido.transport_specific_bindings.ctaphid.handle(buffer[0..bufsize], &auth)` where `buffer` contains the raw data and `auth` is the authenticator instance
7. `ctaphid.handle` will either return null (if its still in the process of assembling the request) or an iterator (containing the response). You can call `next()` on the iterator to get the next CTAPHID packet to send to the client.
```zig
// example of sending a CTAPHID response (tinyusb)
if (response != null) {
    while (response.?.next()) |r| {
        while (!tudHidReady()) {
            tudTask();
            // wait until ready
        }

        _ = tudHidReport(0, r);
    }
}
```

#### Examples

| Platform | Architecture | Link |
|:--------:|:------------:|:----:|
| nRF52840-MDK USB Dongle | Arm | [candy-stick-nrf](https://github.com/r4gus/candy-stick-nrf) |

### Supported transport specific bindings

| binding           | supported? |
|:-----------------:|:----------:|
| USB | ✅ |
| NFC |    |
| Bluetooth |   |


### Supported commands

| command           | supported? |
|:-----------------:|:----------:|
| `authenticatorMakeCredential`     | ✅ |
| `authenticatorGetAssertion`       | ✅ |
| `authenticatorGetNextAssertion`   |    |
| `authenticatorGetInfo`            | ✅ |
| `authenticatorClientPin`          | ✅ |
| `authenticatorReset`              | ✅ |
| `authenticatorBioEnrollment`      |    |
| `authenticatorCredentialManagement` |    |
| `authenticatorSelection`          |    |
| `authenticatorLargeBlobs`         |    |
| `authenticatorConfig`             |    |

### Crypto

TODO: rewrite this section

</details>

## Resources

- [CTAP2](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#intro) - FIDO Alliance
- [WebAuthn](https://www.w3.org/TR/webauthn-3/) - W3C
- [CBOR RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html) - C. Bormann and P. Hoffman
