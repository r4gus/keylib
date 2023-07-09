# fido2 library

![GitHub](https://img.shields.io/github/license/r4gus/ztap?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/r4gus/fido2/main.yml?style=flat-square)

> _Warning_: NOT PRODUCTION READY!

A library that allows you to implement FIDO2 authenticators. 

![Login Showcase](login.gif)
![Passkey Showcase](login2.gif)

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
  - `std.rand.Random` - A Zig interface of type `std.rand.Random` (e.g., `std.crypto.random`)
  - `pub fn millis() i64` - The time in milliseconds since startup, the epoch time, or something similar (e.g., `std.time.milliTimestamp`)
  - `pub fn up(reason: UpReason, user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) UpResult` - Request permission from the user (e.g., button press)
  - `pub fn uv() bool` - (OPTIONAL): Callback for a built-in user verification method
  - `pub fn getEntry(id: []const u8) ?*cks.Entry` - Load an [Entry](https://github.com/r4gus/fido2/blob/main/cks/Entry.zig) with the given `id`. A `Entry` either represents the general settings of the authenticator (the library assumes that a entry with the id `Settings` is always available) or a resident (discoverable) credential. 
  - `pub fn addEntry(entry: cks.Entry) cks.Error!void` - The given entry should be added to a set of existing entries. _NOTE: If you don't want to support resident keys, you can just return an error by default_.
  - `pub fn createEntry(id: []const u8) cks.Error!cks.Entry` - Create a new entry with the given id. _NOTE: If you don't want to support resident keys, you can just return an error by default_.
  - `pub fn getEntries() ?[]cks.Entry` - Get a slice of all entries available. _NOTE: If you don't want to support resident keys, you can just return an error by default_.
  - `pub fn persist() error{Fatal}!void` - Persist all changes made to entries. This function has to be implemented because the `Settings` entry will change from time to time and those changes have to be persisted.
  - `pub fn reset() void` - Reset the authenticator. The currently set pin and all credentials have to be invalidated!
  - `pub fn validate_pin_constraints(pin: []const u8) bool` - (OPTIONAL): This allows the implementation of arbitrary pin constraints.
4. On startup create a new authenticator instance, defining its capabilities:
```zig
var authenticator = fido.ctap.authenticator.Authenticator{
    .settings = .{
        .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
        .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
        .options = .{
            .uv = false,
            // This is a platform authenticator even if we use usb for ipc
            .plat = true,
            // Set clientPin to false if you wanna support a pin and to none
            // if you don't want to use a pin at all. Never set this to true!
            .clientPin = false,
            .pinUvAuthToken = true,
            .alwaysUv = true,
        },
        .pinUvAuthProtocols = &.{.V2},
        .transports = &.{.usb},
        // Please make sure that this list matches the (algorithms) list below!
        .algorithms = &.{.{ .alg = .Es256 }},
        .firmwareVersion = 0xcafe,
    },
    .attestation_type = .Self,
    .callbacks = .{
        .rand = std.crypto.random,
        .millis = std.time.milliTimestamp,
        .up = callbacks.up,
        .createEntry = callbacks.createEntry,
        .getEntry = callbacks.getEntry,
        .getEntries = callbacks.getEntries,
        .addEntry = callbacks.addEntry,
        .persist = callbacks.persist,
        .reset = callbacks.reset,
    },
    .algorithms = &.{
        fido.ctap.crypto.algorithms.Es256,
    },
    .token = .{
        //.one = fido.ctap.pinuv.PinUvAuth.v1(callbacks.rand),
        .two = fido.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
    },
    .allocator = allocator,
};

if (authenticator.token.one) |*one| {
    one.initialize();
}
if (authenticator.token.two) |*two| {
    two.initialize();
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
| `authenticatorReset`              | ✅ |
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

The following signature algorithms (`fido.ctap.crypto.SigAlg`) are supported
by the library:

| sub-command           | supported? |
|:-----------------:|:----------:|
| Es256 (ECDSA-P256-SHA256)  |  ✅  |

You can add more algorithms by instantiating [`SigAlg`](https://github.com/r4gus/fido2/blob/main/lib/ctap/crypto/SigAlg.zig) and adding your
instance to `Authenticator.algorithms`.

Each `SigAlg` instance has a `cbor.cose.Algorithm` field, a `create` and a `sign` function.

* `create` - Create a new key pair (see: `fido.ctap.crypto.SigAlg.KeyPair`). The `KeyPair`s
`cose_public_key` field should contain the CBOR encoded [COSE](https://datatracker.ietf.org/doc/html/rfc8152) public key and the `raw_private_key` should contain the raw private key.

* `sign` - Function for signing data. It takes the private key generated by `create`.

See `lib/ctap/crypto/sigalgs/Es256.zig` for reference.

### Linux platform authenticator

There is a (very incomplete but working) platform authenticator available in `./platform-auth`.
To set it up you can run the following commands from the command line:

1. install udev rules
TODO: Provide udev rules

3. Run the authenticator
```
zig build
./zig-out/bin/platauth
```
All the stuff here is still very experimental!

### Are we yet?

This is all theoretical! At the end it depends on the actual configuration.

#### Are we FIDO\_2\_1 yet?

| requirement           | supported? |
|:-----------------:|:----------:|
| MUST support the hmac-secret extension  | |
| clientPin or uv + resident key  |  ✅  |
| credMgmt  | |
| MUST support credProtect extension |  ✅  |
| pinUvAuthToken  |  ✅  |
| PIN/UV auth protocol two support |  ✅  |
    
</details>

## Resources

- [CTAP2](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#intro) - FIDO Alliance
- [WebAuthn](https://www.w3.org/TR/webauthn-3/) - W3C
- [CBOR RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html) - C. Bormann and P. Hoffman

---

- [Passkey test site](https://passkey.org/)
- [FIDO2 test site](https://webauthn.io/)
