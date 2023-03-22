# fido2 library

![GitHub](https://img.shields.io/github/license/r4gus/ztap?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/r4gus/fido2/main.yml?style=flat-square)

> _Warning_: NOT PRODUCTION READY!

A library wich allows you to implement FIDO2 authenticators and client applications. 

<details>
<summary><ins>Getting started</ins></summary>
To use this library you can either add it directly as a module or use the Zig package manager to fetch it as a dependency.

### Zig package manager

First add this library as dependency to your build.zig.zon file:

```zon
.{
    .name = "your-project",
    .version = 0.0.1,

    .dependencies = .{
        .fido = .{
            .url = "https://github.com/r4gus/fido2/archive/main.tar.gz",
            .hash = "122036646fd5c72c265f2eb4dfc4b9891696a38e7c614b234b3ea65795eb2584d052",
        }
    },
}
```

#### Hash

To calculate the hash you can use the following [script](https://github.com/r4gus/zig-package-hash/blob/main/hash.sh).

> Note: The Zig core team might alter the hashing algorithm used, i.e., the script might
> not always calculate the correct result in the future.

### As a module

First add the library to your project, e.g., as a submodule:

```
your-project$ mkdir libs
your-project$ git submodule add https://github.com/r4gus/fido2.git libs/fido
```

Then add the following line to your `build.zig` file.

```zig
// Create a new module
var fido_module = b.createModule(.{
    .source_file = .{ .path = "libs/fido/lib/main.zig" },
});

// create your exe ...

// Add the module to your exe/ lib
exe.addModule("fido", fido_module);
```

</summary>

<details>
<summary><ins>FIDO2 authenticator</ins></summary>

You can use this library to implement roaming and platform FIDO2 authenticators. It makes no assumptions about the
underlying hardware, instead the user of this library is responsible to provide the necessary resources (see below).

### Getting started

The following steps are required to get started:

1. Add this repository to your project
2. Implement a basic application that acts as a raw usb hid device (nfc and bluetooth are currently not supported)
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

<details>
<summary><ins>FIDO2 tooling</ins></summary>
</details>

## Resources

- [CTAP2](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#intro) - FIDO Alliance
- [WebAuthn](https://www.w3.org/TR/webauthn-3/) - W3C
- [CBOR RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html) - C. Bormann and P. Hoffman
