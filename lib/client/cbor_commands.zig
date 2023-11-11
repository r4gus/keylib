const std = @import("std");
const keylib = @import("../main.zig");
const cbor = @import("zbor");
const Transport = @import("Transport.zig");
const err = @import("error.zig");

// ///////////////////////////////////////
// Get Info
// ///////////////////////////////////////

pub const Info = keylib.ctap.authenticator.Settings;

pub fn authenticatorGetInfo(t: *Transport, a: std.mem.Allocator) !Info {
    const cmd = "\x04";

    try t.write(cmd);
    if (try t.read(a)) |response| {
        defer a.free(response);
        return try cbor.parse(Info, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
    } else {
        return error.MissingResponse;
    }
}

// ///////////////////////////////////////
// Credential
// ///////////////////////////////////////

pub const credentials = struct {
    pub const PublicKey = struct {
        // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#publickey_object_structure

        pub const Attestation = enum {
            none,
            direct,
            enterprise,
            indirect,
        };

        pub const Formats = enum {
            @"packed",
            tpm,
            @"android-key",
            @"android-safetynet",
            @"fido-u2f",
            apple,
            none,
        };

        pub const Attachment = enum {
            platform,
            @"cross-platform",
        };

        pub const Requirements = enum {
            discouraged,
            preferred,
            required,
        };

        pub const Transports = enum {
            ble,
            hybrid,
            internal,
            nfc,
            usb,
        };

        pub const ExcludeCredential = struct {
            id: []const u8,
            transports: []const Transports,
            type: []const u8 = "public-key",
        };

        pub const PubKeyCredParam = struct {
            alg: i32,
            type: []const u8 = "public-key",
        };

        pub const Hints = enum {
            @"security-key",
            @"client-device",
            hybrid,
        };

        attestation: ?[]const u8 = null,
        attestationFormats: ?[]const Formats = null,
        authenticatorSelection: ?struct {
            authenticatorAttachment: ?Attachment = null,
            requireResidentKey: ?bool = null,
            residentKey: ?Requirements = null,
            userVerification: ?Requirements = null,
        } = null,
        challenge: []const u8,
        excludeCredentials: ?[]const ExcludeCredential = null,
        allowCredentials: ?[]const keylib.common.PublicKeyCredentialDescriptor = null,
        pubKeyCredParams: ?[]const PubKeyCredParam = null,
        rp: ?keylib.common.RelyingParty = null,
        rpId: ?[]const u8 = null,
        /// The time in ms the rp is willing to wait
        timeout: i64 = 300000,
        user: ?keylib.common.User = null,
        hints: ?[]const Hints = null,
        userVerification: ?Requirements = null,
    };

    pub const Options = struct {
        protocol: ?keylib.ctap.pinuv.common.PinProtocol = null,
        param: ?[]const u8 = null,
    };

    pub fn create(
        t: *Transport,
        public_key: PublicKey,
        options: Options,
        a: std.mem.Allocator,
    ) !void {
        _ = t;
        _ = public_key;
        _ = options;
        _ = a;
    }

    pub fn get(
        t: *Transport,
        origin: []const u8,
        crossOrigin: bool,
        public_key: PublicKey,
        options: Options,
        a: std.mem.Allocator,
    ) !void {
        if (public_key.rpId == null) {
            return error.RpIdMissing;
        }

        // The challenge is base64 encoded before being integrated into the client data
        const Base64 = std.base64.url_safe.Encoder;
        var challenge = try a.alloc(u8, Base64.calcSize(public_key.challenge.len));
        defer a.free(challenge);
        _ = Base64.encode(challenge, public_key.challenge);

        // Serialize the client data and then hash them...
        const client_data = try serialize(
            a,
            "webauthn.get",
            challenge,
            origin,
            crossOrigin,
        );
        defer a.free(client_data);
        var client_data_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(client_data, client_data_hash[0..], .{});

        const param: ?[]const u8 = if (options.param != null and options.protocol != null) blk: {
            const param = switch (options.protocol.?) {
                .V1 => try PinUvAuth.authenticate_v1(options.param.?, &client_data_hash, a),
                .V2 => try PinUvAuth.authenticate_v2(options.param.?, &client_data_hash, a),
            };
            break :blk param;
        } else blk: {
            break :blk null;
        };
        defer {
            if (param) |p| {
                a.free(p);
            }
        }

        const cmd = 0x02;
        var request = keylib.ctap.request.GetAssertion{
            .rpId = try a.dupeZ(u8, public_key.rpId.?),
            .clientDataHash = client_data_hash,
            .pinUvAuthParam = param,
            .pinUvAuthProtocol = options.protocol,
            .allowList = public_key.allowCredentials,
        };
        defer a.free(request.rpId);

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(cmd);
        try cbor.stringify(request, .{}, arr.writer());

        std.log.info("{s}", .{std.fmt.fmtSliceHexLower(arr.items)});

        try t.write(arr.items);

        const start = std.time.milliTimestamp();

        while (true) {
            if (std.time.milliTimestamp() - start > public_key.timeout) return error.Timeout;

            var resp = t.read(a) catch |e| {
                if (e == error.Processing) {
                    std.log.info("get: processing request", .{});
                    continue;
                } else if (e == error.UpNeeded) {
                    std.log.info("get: waiting for user presence", .{});
                    continue;
                } else {
                    // This is an error we can't handle
                    return e;
                }
            };

            if (resp) |response| {
                defer a.free(response);

                std.log.info("{s}", .{std.fmt.fmtSliceHexLower(response)});

                if (response[0] != 0) {
                    return err.errorFromInt(response[0]);
                }

                return;
            } else {
                // read returns null on (internal) timeout
                continue;
            }
        }
    }

    pub fn serialize(
        a: std.mem.Allocator,
        typ: []const u8,
        challenge: []const u8,
        origin: []const u8,
        crossOrigin: bool,
    ) ![]const u8 {
        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();

        try out.appendSlice("{\"type\":");
        try CCDToString(out.writer(), typ);
        try out.appendSlice(",\"challenge\":");
        try CCDToString(out.writer(), challenge);
        try out.appendSlice(",\"origin\":");
        try CCDToString(out.writer(), origin);
        try out.appendSlice(",\"crossOrigin\":");
        try out.appendSlice(if (crossOrigin) "true" else "false");
        // TODO: handle tokenBinding
        try out.appendSlice("}");

        return try out.toOwnedSlice();
    }

    pub fn CCDToString(out: anytype, in: []const u8) !void {
        var i: usize = 0;

        std.log.info("{s}", .{in});

        try out.writeByte(0x22);
        while (i < in.len) : (i += 1) {
            const l = try std.unicode.utf8ByteSequenceLength(in[i]);
            const cp = try std.unicode.utf8Decode(in[i .. i + l]);

            switch (cp) {
                0x20, 0x21, 0x23...0x5b, 0x5d...0x10ffff => try out.writeAll(in[i .. i + l]),
                0x22 => try out.writeAll(&.{ 0x5c, 0x22 }),
                0x5c => try out.writeAll(&.{ 0x5c, 0x22 }),
                else => {
                    var tmp: [4]u8 = .{0} ** 4;
                    @memcpy(tmp[0..l], in[i .. i + l]);
                    try out.writeAll(&.{ 0x5c, 0x75 });
                    try out.print("{x:2}{x:2}{x:2}{x:2}", .{ tmp[3], tmp[2], tmp[1], tmp[0] });
                },
            }
        }
        try out.writeByte(0x22);
    }
};

// ///////////////////////////////////////
// Client Pin
// ///////////////////////////////////////

pub const PinUvAuth = keylib.ctap.pinuv.PinUvAuth;
pub const ClientPin = keylib.ctap.request.ClientPin;
pub const ClientPinResponse = keylib.ctap.response.ClientPin;
pub const EcdhP256 = keylib.ctap.crypto.dh.EcdhP256;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const client_pin = struct {
    pub const Encapsulation = struct {
        version: keylib.ctap.pinuv.common.PinProtocol,
        platform_key_agreement_key: keylib.ctap.crypto.dh.EcdhP256.KeyPair,
        shared_secret: []const u8 = undefined,
        allocator: std.mem.Allocator,

        pub fn deinit(self: @This()) void {
            self.allocator.free(self.shared_secret);
        }
    };

    pub fn encapsulate(
        version: keylib.ctap.pinuv.common.PinProtocol,
        peer_cose_key: cbor.cose.Key,
        a: std.mem.Allocator,
    ) !Encapsulation {
        var seed: [EcdhP256.secret_length]u8 = undefined;
        std.crypto.random.bytes(seed[0..]);
        var k = try EcdhP256.KeyPair.create(seed);

        const shared_point = try EcdhP256.scalarmultXY(
            k.secret_key,
            peer_cose_key.P256.x,
            peer_cose_key.P256.y,
        );

        const z: [32]u8 = shared_point.toUncompressedSec1()[1..33].*;

        var ss = switch (version) {
            .V1 => try PinUvAuth.kdf_v1(z, a),
            .V2 => try PinUvAuth.kdf_v2(z, a),
        };

        return .{
            .version = version,
            .platform_key_agreement_key = k,
            .shared_secret = ss,
            .allocator = a,
        };
    }

    pub fn getKeyAgreement(
        t: *Transport,
        version: keylib.ctap.pinuv.common.PinProtocol,
        a: std.mem.Allocator,
    ) !Encapsulation {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = version,
            .subCommand = .getKeyAgreement,
        };

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(cmd);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer cpr.deinit(a);

            if (cpr.keyAgreement == null) return error.MissingPar;

            return try encapsulate(version, cpr.keyAgreement.?, a);
        } else {
            return error.MissingResponse;
        }
    }

    pub const Permissions = packed struct {
        mc: u1 = 0,
        ga: u1 = 0,
        cm: u1 = 0,
        be: u1 = 0,
        lbw: u1 = 0,
        acfg: u1 = 0,
        reserved1: u1 = 0,
        reserved2: u1 = 0,
    };

    pub fn getPinToken(
        t: *Transport,
        e: *Encapsulation,
        pin: []const u8,
        a: std.mem.Allocator,
    ) ![]const u8 {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .getPinToken,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
        };

        var pin_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(pin, &pin_hash, .{});
        const pin_hash_left = pin_hash[0..16];

        var _pinHashEnc: [32]u8 = undefined;
        var pinHashEnc: []u8 = undefined;
        switch (e.version) {
            .V1 => {
                var iv: [16]u8 = .{0} ** 16;
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret[0..32].*,
                    _pinHashEnc[0..16],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..16];
            },
            .V2 => {
                std.crypto.random.bytes(_pinHashEnc[0..16]);
                PinUvAuth._encrypt(
                    _pinHashEnc[0..16].*,
                    e.shared_secret[32..64].*,
                    _pinHashEnc[16..32],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..32];
            },
        }
        request.pinHashEnc = pinHashEnc;

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(cmd);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer cpr.deinit(a);

            if (cpr.pinUvAuthToken == null) return error.MissingPar;

            var token: []u8 = undefined;
            switch (e.version) {
                .V1 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len);
                    PinUvAuth.decrypt_v1(e.shared_secret, token, cpr.pinUvAuthToken.?);
                },
                .V2 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len - 16);
                    PinUvAuth.decrypt_v2(e.shared_secret, token, cpr.pinUvAuthToken.?);
                },
            }
            return token;
        } else {
            return error.MissingResponse;
        }
    }

    pub fn getPinUvAuthTokenUsingPinWithPermissions(
        t: *Transport,
        e: *Encapsulation,
        permissions: Permissions,
        rpId: ?[]const u8,
        pin: []const u8,
        a: std.mem.Allocator,
    ) ![]const u8 {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .getPinUvAuthTokenUsingPinWithPermissions,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
            .permissions = std.mem.toBytes(permissions)[0],
        };

        if (rpId) |id| {
            request.rpId = id;
        }

        var pin_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(pin, &pin_hash, .{});
        const pin_hash_left = pin_hash[0..16];

        var _pinHashEnc: [32]u8 = undefined;
        var pinHashEnc: []u8 = undefined;
        switch (e.version) {
            .V1 => {
                var iv: [16]u8 = .{0} ** 16;
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret[0..32].*,
                    _pinHashEnc[0..16],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..16];
            },
            .V2 => {
                std.crypto.random.bytes(_pinHashEnc[0..16]);
                PinUvAuth._encrypt(
                    _pinHashEnc[0..16].*,
                    e.shared_secret[32..64].*,
                    _pinHashEnc[16..32],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..32];
            },
        }
        request.pinHashEnc = pinHashEnc;

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(cmd);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer cpr.deinit(a);

            if (cpr.pinUvAuthToken == null) return error.MissingPar;

            var token: []u8 = undefined;
            switch (e.version) {
                .V1 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len);
                    PinUvAuth.decrypt_v1(e.shared_secret, token, cpr.pinUvAuthToken.?);
                },
                .V2 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len - 16);
                    PinUvAuth.decrypt_v2(e.shared_secret, token, cpr.pinUvAuthToken.?);
                },
            }
            return token;
        } else {
            return error.MissingResponse;
        }
    }
};

// ///////////////////////////////////////
// Credential Management
// ///////////////////////////////////////

pub const CredentialManagement = keylib.ctap.request.CredentialManagement;
pub const CredentialManagementResponse = keylib.ctap.response.CredentialManagement;

pub const cred_management = struct {
    pub const RpResponse = struct {
        rp: keylib.common.RelyingParty,
        //rpIDHash: []const u8,
        total: ?u32 = null,
        a: std.mem.Allocator,

        pub fn deinit(self: *const @This()) void {
            self.a.free(self.rp.id);
            if (self.rp.name != null) self.a.free(self.rp.name.?);
            //self.a.free(self.rpIDHash);
        }
    };

    pub fn enumerateRPsBegin(
        t: *Transport,
        protocol: keylib.ctap.pinuv.common.PinProtocol,
        param: []const u8,
        a: std.mem.Allocator,
        is_yubikey: bool,
    ) !?RpResponse {
        const _param = switch (protocol) {
            .V1 => try PinUvAuth.authenticate_v1(param, "\x02", a),
            .V2 => try PinUvAuth.authenticate_v2(param, "\x02", a),
        };
        defer a.free(_param);

        const request = CredentialManagement{
            .subCommand = .enumerateRPsBegin,
            .pinUvAuthProtocol = protocol,
            .pinUvAuthParam = _param,
        };

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.rp == null) return null; // this doesn't reflect the spec but its the behaviour of yubikeys
            if (r.rpIDHash == null) return error.MissingPar;
            if (r.totalRPs == null) return error.MissingPar;

            return .{
                .rp = .{
                    .id = try a.dupe(u8, r.rp.?.id),
                    .name = if (r.rp.?.name != null) try a.dupe(u8, r.rp.?.name.?) else null,
                },
                //.rpIDHash = try a.dupe(u8, r.rpIDHash.?),
                .total = r.totalRPs.?,
                .a = a,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateRPsGetNextRP(
        t: *Transport,
        a: std.mem.Allocator,
        is_yubikey: bool,
    ) !?RpResponse {
        const request = CredentialManagement{
            .subCommand = .enumerateRPsGetNextRP,
        };

        var arr = std.ArrayList(u8).init(a);
        defer arr.deinit();

        try arr.append(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, arr.writer());

        try t.write(arr.items);

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.rp == null) return null; // this doesn't reflect the spec but its the behaviour of yubikeys
            if (r.rpIDHash == null) return error.MissingPar;

            return .{
                .rp = .{
                    .id = try a.dupe(u8, r.rp.?.id),
                    .name = if (r.rp.?.name != null) try a.dupe(u8, r.rp.?.name.?) else null,
                },
                //.rpIDHash = try a.dupe(u8, r.rpIDHash.?),
                .a = a,
            };
        } else {
            return error.MissingResponse;
        }
    }
};
