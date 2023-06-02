# fido2 library

![GitHub](https://img.shields.io/github/license/r4gus/ztap?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/r4gus/fido2/main.yml?style=flat-square)

> _Warning_: NOT PRODUCTION READY!

A library wich allows you to implement FIDO2 authenticators and client applications. 

<details>
<summary><ins>Getting started</ins></summary>
To use this library you can either add it directly as a module or use the Zig package manager to fetch it as a dependency.

### Zig package manager

First add this library as dependency to your build.zig.zon file, e.g.,:

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

Currently, the easiest way to get the correct hash value is to flip the last digit and then try to run `zig build`.
The actual hash will be listed in the error message.

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

</details>

<details>
<summary><ins>FIDO2 authenticator</ins></summary>

You can use this library to implement roaming and platform FIDO2 authenticators. It makes no assumptions about the
underlying hardware, instead the user of this library is responsible to provide the necessary resources (see below).

### Getting started

The following steps are required to get started:

1. Add this repository to your project
2. Implement a basic application that acts as a raw usb hid device (nfc and bluetooth are currently not supported, but you could write the transport code yourself)
3. Define the following callbacks:
  - `pub fn rand(b: []u8) void` - Fill the given buffer with random bytes 
  - `pub fn millis() u64` - The time in milliseconds since startup, the epoch time, or something similar
  - `pub fn up(user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) bool` - Request permission from the user (e.g., button press)
  - `pub fn uv() bool` - (OPTIONAL): Callback for a built-in user verification method
  - `pub fn loadCurrentStoredPIN() LoadError![32]u8` - Load the currently stored pin hash (you must take care to store this in a safe way)
  - `pub fn storeCurrentStoredPIN(d: [32]u8) void` - Store the new pin hash (you must take care to store this in a safe way)
  - `pub fn loadPINCodePointLength() LoadError!u8` - Load the length of the pin (you must take care to store this in a safe way)
  - `pub fn storePINCodePointLength(d: u8) void` - Store the new pin length (you must take care to store this in a safe way)
  - `pub fn get_retries() LoadError!u8` - Load the number of pin retries left (you must take care to store this in a safe way)
  - `pub fn set_retries(r: u8) void` - Set the number of retries to the given value (you must take care to store this in a safe way)
  - `pub fn load_credential_by_id(id: []const u8, a: std.mem.Allocator) LoadError![]const u8` - Load the cbor encoded credential with the given id 
    (you must take care to store this in a safe way)
  - `pub fn store_credential_by_id(id: []const u8, d: []const u8) void` - Store the given cbor encoded credential with the given id 
    (you must take care to store this in a safe way)
4. On startup create a new authenticator instance, defining its capabilities:
```zig
var authenticator = fido.ctap.authenticator.Authenticator{
    .settings = .{
        .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
        .aaguid = "\x7f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
        .options = .{
            // This is a platform authenticator even if we use usb for ipc
            .plat = true,
            // THe device is capable of accepting a PIN from the client
            .clientPin = true,
        },
        .pinUvAuthProtocols = &.{.V2},
        .transports = &.{.usb},
        .algorithms = &.{.{ .alg = .Es256 }},
        .firmwareVersion = 0xcafe,
    },
    .attestation_type = .Self,
    .callbacks = .{
        .rand = callbacks.rand,
        .millis = callbacks.millis,
        .up = callbacks.up,
        .loadCurrentStoredPIN = callbacks.loadCurrentStoredPIN,
        .storeCurrentStoredPIN = callbacks.storeCurrentStoredPIN,
        .loadPINCodePointLength = callbacks.loadPINCodePointLength,
        .storePINCodePointLength = callbacks.storePINCodePointLength,
        .get_retries = callbacks.get_retries,
        .set_retries = callbacks.set_retries,
        .load_credential_by_id = callbacks.load_credential_by_id,
        .store_credential_by_id = callbacks.store_credential_by_id,
    },
    .token = .{
        //.one = fido.ctap.pinuv.PinUvAuth.v1(callbacks.rand),
        .two = fido.ctap.pinuv.PinUvAuth.v2(callbacks.rand),
    },
    .allocator = gpa.allocator(),
};

// Make sure to call initialize() on every pinUvProtocol you want to use!
if (authenticator.token.one) |*one| {
    one.initialize(authenticator.callbacks.rand);
}
if (authenticator.token.two) |*two| {
    two.initialize(authenticator.callbacks.rand);
}

```
6. On receiving a usb packet call `fido.ctap.transports.ctaphid.authenticator.handle(buffer[0..bufsize], &auth)` where `buffer` contains the raw data and `auth` is the authenticator instance
7. `ctaphid.handle` will either return null (if its still in the process of assembling the request) or an iterator (containing the response). You can call `next()` on the iterator to get the next CTAPHID packet to send to the client.
```zig
if (response) |*resp| {
    while (resp.next()) |packet| {
        try usb.write(packet);
    }
}
```

#### Examples (outdated)

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
| `authenticatorGetAssertion`       |✅  |
| `authenticatorGetNextAssertion`   |    |
| `authenticatorGetInfo`            | ✅ |
| `authenticatorClientPin`          | ✅ |
| `authenticatorReset`              | |
| `authenticatorBioEnrollment`      |    |
| `authenticatorCredentialManagement` |    |
| `authenticatorSelection`          |  ✅   |
| `authenticatorLargeBlobs`         |    |
| `authenticatorConfig`             |    |

#### Supported clientPin commands

| sub-command           | supported? |
|:-----------------:|:----------:|
| `getPINRetries`     |  ✅  |
| `getKeyAgreement`     |  ✅  |
| `setPIN`     |  ✅  |
| `changePIN`     |  ✅  |
| `getPinToken`     |  |
| `getPinUvAuthTokenUsingUvWithPermission`     |  |
| `getUVRetries`     |  |
| `getPinUvAuthTokenUsingPinWithPermission`     |  ✅  |

### Supported signature algorithms

| sub-command           | supported? |
|:-----------------:|:----------:|
| Es256 (ECDSA-P256-SHA256)  |  ✅  |


<details>
<summary><ins>Capabilities</ins></summary>
    * If you want to use the `clientPinUv` protocol, make sure to follow these steps:
        1. In `Settings.options` set `clientPin` and `pinUvAuthToke` both to `true`
        2. Implement `loadCurrentStoredPIN`, `storeCurrentStoredPIN`, `loadPINCodePointLength` and `storePINCodePointLength`
        3. Set at least one of the pin protocol versions in `Authenticator.token`, e.g. `.two = fido.ctap.pinuv.PinUvAuth.v2(callbacks.rand)`
        4. Make sure you call `initialize` after the authenticator instantiation for every pin protocol
</details>

</details>

<details>
<summary><ins>FIDO2 Client</ins></summary>

The code found in `fido2.client` can be used to implement FIDO2 clients (WIP). The client library
defines a `Authenticator` struct that represents an abstract authenticator with basic IO operations
like `open()`, `close()`, `read()` and `write()`. Those operations use a `Transport` (this can be
anything, e.g., USB, NFC, or IPC via sockets) to communicate with an authenticator. The specific
transport implementations can be found in `fido2.client.transports` (The plan is to add different
transports to the library over time but you should be able to implement your own transports if you
want).

## Usage

The library can be used as follows:

1.  Choose one or more transports from `fido2.client.transports` (e.g., `usb`) and call `enumerate`
    to get a list of all possible authenticators connected.
2.  You can open a connection to a specific authenticator by calling `open()` on a `Authenticator`
    object returned by `enumerate`. This will establish a connection to the specified authenticator
    (for USB this will allocate a CID automatically).
3.  After you have successfully established a connection, you can call the commands in `fido2.client.commands`
    passing the `Authenticator` object (e.g., `authenticatorGetInfo`).

> Note: This is WIP, i.e., the API may change

## Dependencies

If you want to use certain transports please add the following to your build script:

### USB via hidapi

```zig
// TODO
```

</details>

<details>
<summary><ins>FIDO2 tooling</ins></summary>

This library comes with a (very incomplete) command line tool which lets you interact with
a fido device connected via usb.

> NOTE: stay tuned for more...

</details>

## Resources

- [CTAP2](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#intro) - FIDO Alliance
- [WebAuthn](https://www.w3.org/TR/webauthn-3/) - W3C
- [CBOR RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html) - C. Bormann and P. Hoffman
