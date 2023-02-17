/// Client to Authenticator (CTAP) library
const std = @import("std");

pub const ctaphid = @import("ctaphid.zig");

pub const crypt = @import("crypto.zig");
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
pub const Ecdsa = crypt.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;
pub const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const EcdhP256 = crypt.ecdh.EcdhP256;
pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Aes256 = std.crypto.core.aes.Aes256;

pub const ms_length = Hmac.mac_length;
pub const pin_len: usize = 16;
// VALID || MASTER_SECRET || PIN || CTR || RETRIES || padding
pub const data_len = 1 + ms_length + pin_len + 4 + 1 + 2;

const dobj = @import("dobj.zig");

pub const Versions = dobj.Versions;
pub const User = dobj.User;
pub const RelyingParty = dobj.RelyingParty;

const cbor = @import("zbor");
const cose = cbor.cose;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DataItem = cbor.DataItem;
const Pair = cbor.Pair;

const commands = @import("commands.zig");
pub const Commands = commands.Commands;
const getCommand = commands.getCommand;
const MakeCredentialParam = commands.make_credential.MakeCredentialParam;
const GetAssertionParam = commands.get_assertion.GetAssertionParam;
const GetAssertionResponse = commands.get_assertion.GetAssertionResponse;
const extension = @import("extensions.zig");
pub const Extensions = extension.Extensions;
const ClientPinParam = commands.client_pin.ClientPinParam;
const ClientPinResponse = commands.client_pin.ClientPinResponse;
const PinUvAuthTokenState = commands.client_pin.PinUvAuthTokenState;
const PinConf = commands.client_pin.PinConf;

const data_module = @import("data.zig");

/// General properties of a given authenticator.
pub const Info = struct {
    /// versions: List of supported versions.
    @"1": []const dobj.Versions,
    /// extensions: List of supported extensions.
    @"2": ?[]const Extensions,
    /// aaguid: The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
    /// indicating the type of the authenticator. Authenticators with the
    /// same capabilities and firmware, can share the same AAGUID.
    @"3": [16]u8,
    /// optoins: Supported options.
    @"4": ?dobj.Options,
    /// maxMsgSize: Maximum message size supported by the authenticator.
    /// null = unlimited.
    @"5": ?u64,
    /// pinProtocols: List of supported PIN Protocol versions.
    @"6": ?[]const u8, // TODO: add _a option to enforce array
};

pub const AttType = enum {
    /// In this case, no attestation information is available.
    none,
    /// In the case of self attestation, also known as surrogate basic attestation [UAFProtocol], the
    /// Authenticator does not have any specific attestation key pair. Instead it uses the credential private key
    /// to create the attestation signature. Authenticators without meaningful protection measures for an
    /// attestation private key typically use this attestation type.
    self,
};

pub const AttestationType = struct {
    att_type: AttType = AttType.self,
};

pub fn Auth(comptime impl: type) type {
    return struct {
        const Self = @This();

        /// General properties of the given authenticator.
        info: Info,
        /// Attestation type to be used for attestation.
        attestation_type: AttestationType,

        /// Default initialization without extensions.
        pub fn initDefault(versions: []const dobj.Versions, aaguid: [16]u8) Self {
            return @This(){
                .info = Info{
                    .@"1" = versions,
                    .@"2" = null,
                    .@"3" = aaguid,
                    .@"4" = dobj.Options{}, // default options
                    .@"5" = null,
                    .@"6" = null,
                },
                .attestation_type = AttestationType{},
            };
        }

        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // Interface
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        pub fn loadData(allocator: std.mem.Allocator) !data_module.PublicData {
            var d = impl.load(allocator);
            defer allocator.free(d);
            return try cbor.parse(data_module.PublicData, try cbor.DataItem.new(d), .{ .allocator = allocator });
        }

        pub fn storeData(data: *const data_module.PublicData) void {
            // Lets allocate the required memory on the stack for data
            // serialization.
            var raw: [512]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&raw);
            const allocator = fba.allocator();
            var arr = std.ArrayList(u8).init(allocator);
            defer arr.deinit();
            var writer = arr.writer();

            // reserve bytes for cbor size
            writer.writeAll("\x00\x00\x00\x00") catch unreachable;

            // Serialize PublicData to cbor
            cbor.stringify(data, .{}, writer) catch unreachable;

            // Prepend size. This might help reading back the data if no
            // underlying file system is available.
            const len = @intCast(u32, arr.items.len - 4);
            std.mem.writeIntSliceLittle(u32, arr.items[0..4], len);

            // Now store `SIZE || CBOR`
            impl.store(arr.items[0..]);
        }

        pub fn millis(self: *const Self) u32 {
            _ = self;
            return impl.millis();
        }

        /// This function asks the user in some way for permission,
        /// e.g. button press, touch, key press.
        ///
        /// It returns `true` if permission has been granted, `false`
        /// otherwise (e.g. timeout).
        pub fn requestPermission(user: ?*const dobj.User, rp: ?*const dobj.RelyingParty) bool {
            return impl.requestPermission(user, rp);
        }

        /// Fill the given slice with random data.
        pub fn getBlock(buffer: []u8) void {
            var r: u32 = undefined;

            var i: usize = 0;
            while (i < buffer.len) : (i += 1) {
                if (i % 4 == 0) {
                    // Get a fresh 32 bit integer every 4th iteration.
                    r = impl.rand();
                }

                // The shift value is always between 0 and 24, i.e. int cast will always succeed.
                buffer[i] = @intCast(u8, (r >> @intCast(u5, (8 * (i % 4)))) & 0xff);
            }
        }

        pub fn reset(allocator: std.mem.Allocator, ctr: [12]u8) void {
            const default_pin = "candystick";

            // Prepare secret data
            var secret_data: data_module.SecretData = undefined;
            secret_data.master_secret = crypt.createMasterSecret(getBlock);
            secret_data.pin_hash = crypt.pinHash(default_pin);
            secret_data.pin_length = default_pin.len;
            secret_data.sign_ctr = 0;

            // Prepare public data
            var public_data: data_module.PublicData = undefined;
            defer public_data.deinit(allocator);
            public_data.meta.valid = 0xF1;
            //getBlock(public_data.meta.salt[0..]);
            public_data.meta.salt = "\xcd\xb1\xa6\x1b\xc0\x54\x7a\x3e\x4c\xa7\x61\x88\x4a\xad\x3d\x9f\xfd\x1d\xb1\x16\x77\x71\xf3\x22\x51\x1c\x5a\x42\x16\x2c\x27\xc0".*;
            public_data.meta.nonce_ctr = ctr;
            public_data.meta.pin_retries = 8;

            // Derive key from pin
            const key = Hkdf.extract(public_data.meta.salt[0..], default_pin);

            // Encrypt secret data
            public_data.c = data_module.encryptSecretData(
                allocator,
                &public_data.tag,
                &secret_data,
                key,
                public_data.meta.nonce_ctr,
            ) catch unreachable;

            storeData(&public_data);
        }

        // TODO: is this function redundant after the last change?
        pub fn initData(self: *const Self) void {
            _ = self;
            var raw: [1024]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&raw);
            const allocator = fba.allocator();

            _ = loadData(allocator) catch {
                reset(allocator, [_]u8{0} ** 12);
                return;
            };
        }

        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // CTAP Handler
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        /// Main handler function, that takes a command and returns a response.
        pub fn handle(self: *const Self, allocator: Allocator, command: []const u8) ![]u8 {
            // The response message.
            // For encodings see: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses
            var res = std.ArrayList(u8).init(allocator);
            var response = res.writer();
            try response.writeByte(0x00); // just overwrite if neccessary

            const cmdnr = getCommand(command) catch |err| {
                // On error, respond with a error code and return.
                try response.writeByte(@enumToInt(dobj.StatusCodes.fromError(err)));
                return res.toOwnedSlice();
            };

            const S = struct {
                var initialized: bool = false;
                var state: PinUvAuthTokenState = .{};
            };

            // At power-up, the authenticator calls initialize for each
            // pinUvAuthProtocol that it supports.
            if (!S.initialized) {
                S.state.initialize(getBlock);
                S.initialized = true;
            }

            // Load authenticator data
            var write_back = true; // This gets overwritten by authReset
            var data = loadData(allocator) catch {
                reset(allocator, [_]u8{0} ** 12);

                res.items[0] = @enumToInt(dobj.StatusCodes.ctap1_err_other);
                return res.toOwnedSlice(); // TODO: handle properly
            };
            var secret_data: ?data_module.SecretData = null;
            if (S.state.pin_key) |key| {
                secret_data = data_module.decryptSecretData(
                    allocator,
                    data.c,
                    data.tag[0..],
                    key,
                    data.meta.nonce_ctr,
                ) catch {
                    res.items[0] = @enumToInt(dobj.StatusCodes.ctap1_err_other);
                    return res.toOwnedSlice(); // TODO: handle properly
                };
            }
            defer {
                if (write_back) {
                    if (secret_data) |*sd| {
                        // Update nonce counter
                        var nctr: u96 = std.mem.readIntSliceLittle(u96, data.meta.nonce_ctr[0..]);
                        nctr += 1;
                        var nctr_raw: [12]u8 = undefined;
                        std.mem.writeIntSliceLittle(u96, nctr_raw[0..], nctr);

                        // Encrypt data
                        var tmp_tag: [16]u8 = undefined;
                        const tmp_c = data_module.encryptSecretData(
                            allocator,
                            &tmp_tag,
                            sd,
                            S.state.pin_key.?,
                            nctr_raw,
                        ) catch unreachable;

                        allocator.free(data.c);
                        data.c = tmp_c;
                        std.mem.copy(u8, data.tag[0..], tmp_tag[0..]);
                        data.meta.nonce_ctr = nctr_raw;
                    }

                    // Write data back into long term storage
                    storeData(&data);
                }
                // Free dynamically allocated memory. data must
                // not be used after this.
                data.deinit(allocator);
            }

            switch (cmdnr) {
                .authenticator_make_credential => {
                    const mcp_raw = cbor.DataItem.new(command[1..]) catch {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_invalid_cbor);
                        return res.toOwnedSlice();
                    };
                    const mcp = cbor.parse(MakeCredentialParam, mcp_raw, .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => dobj.StatusCodes.ctap2_err_missing_parameter,
                            else => dobj.StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    defer mcp.deinit(allocator);

                    // TODO: Check exclude list (but we dont store any creds!)

                    // Check for a valid COSEAlgorithmIdentifier value
                    var valid_param: bool = false;
                    for (mcp.@"4") |param| {
                        if (crypt.isValidAlgorithm(param.alg)) {
                            valid_param = true;
                            break;
                        }
                    }
                    if (!valid_param) {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_unsupported_algorithm);
                        return res.toOwnedSlice();
                    }

                    // Process all given options
                    if (mcp.@"7") |options| {
                        if (options.rk or options.uv) {
                            // we let the RP store the context for each credential.
                            res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_unsupported_option);
                            return res.toOwnedSlice();
                        }
                    }

                    // 4. Optionally, if the extensions parameter is present, process
                    // any extensions that this authenticator supports.
                    // TODO: support extensions

                    // 5. If pinAuth parameter is present and pinProtocol is 1, verify
                    // it by matching it against first 16 bytes of HMAC-SHA-256 of
                    // clientDataHash parameter using pinToken:
                    // HMAC-SHA-256(pinToken, clientDataHash).
                    //     * If the verification succeeds, set the "uv" bit to 1
                    //       in the response.
                    //     * If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID
                    //       error.
                    if (mcp.@"8") |pinAuth| {
                        _ = pinAuth;
                        if (mcp.@"9" != null and mcp.@"9".? == 1) {
                            // TODO: verify
                        }
                    }

                    // 6. If pinAuth parameter is not present and clientPin been set on
                    // the authenticator, return CTAP2_ERR_PIN_REQUIRED error.
                    // TODO: support clientPin

                    // 7. If pinAuth parameter is present and the pinProtocol is not
                    // supported, return CTAP2_ERR_PIN_AUTH_INVALID.
                    // TODO: implement

                    // Request permission from the user
                    if (!requestPermission(&mcp.@"3", &mcp.@"2")) {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_operation_denied);
                        return res.toOwnedSlice();
                    }

                    if (secret_data == null) {
                        // Decrypting the secret data requires a key derived from the
                        // pin that has the same lifetime as the token, i.e., we use
                        // the presence of secret data to check that the user has authenticated
                        // herself.
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_pin_required);
                        return res.toOwnedSlice();
                    }

                    // Generate a new credential key pair for the algorithm specified.
                    const context = crypt.newContext(getBlock);
                    const key_pair = crypt.deriveKeyPair(secret_data.?.master_secret, context) catch unreachable;

                    // 10. If "rk" in options parameter is set to true.
                    //     * If a credential for the same RP ID and account ID already
                    //       exists on the authenticator, overwrite that credential.
                    //     * Store the user parameter along the newly-created key pair.
                    //     * If authenticator does not have enough internal storage to
                    //       persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
                    // TODO: Resident key support currently not planned

                    // Create a new credential id
                    const cred_id = crypt.makeCredId(secret_data.?.master_secret, &context, mcp.@"2".id);

                    // 11. Generate an attestation statement for the newly-created
                    // key using clientDataHash.
                    const acd = dobj.AttestedCredentialData{
                        .aaguid = self.info.@"3",
                        .credential_length = crypt.cred_id_len,
                        // context is used as id to later retrieve actual key using
                        // the master secret.
                        .credential_id = &cred_id,
                        .credential_public_key = crypt.getCoseKey(key_pair),
                    };

                    var ad = dobj.AuthData{
                        .rp_id_hash = undefined,
                        .flags = dobj.Flags{
                            .up = 1,
                            .rfu1 = 0,
                            .uv = 0,
                            .rfu2 = 0,
                            .at = 1,
                            .ed = 0,
                        },
                        .sign_count = secret_data.?.sign_ctr,
                        .attested_credential_data = acd,
                    };
                    secret_data.?.sign_ctr += 1;

                    // Calculate the SHA-256 hash of the rpId (base url).
                    std.crypto.hash.sha2.Sha256.hash(mcp.@"2".id, &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    // Create attestation statement
                    var stmt: ?dobj.AttStmt = null;
                    if (self.attestation_type.att_type == .self) {
                        const sig = crypt.sign(key_pair, authData.items, mcp.@"1") catch {
                            res.items[0] = @enumToInt(dobj.StatusCodes.ctap1_err_other);
                            return res.toOwnedSlice();
                        };

                        var x: [crypt.der_len]u8 = undefined;
                        stmt = dobj.AttStmt{ .@"packed" = .{
                            .@"#alg" = cose.Algorithm.Es256,
                            .sig = sig.toDer(&x),
                        } };
                    } else {
                        stmt = dobj.AttStmt{ .none = .{} };
                    }

                    const ao = dobj.AttestationObject{
                        .@"1" = dobj.Fmt.@"packed",
                        .@"2" = authData.items,
                        .@"3" = stmt.?,
                    };

                    cbor.stringify(ao, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(dobj.StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_get_assertion => {
                    const gap = cbor.parse(GetAssertionParam, try cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => dobj.StatusCodes.ctap2_err_missing_parameter,
                            else => dobj.StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    defer gap.deinit(allocator);

                    // 1. locate all denoted credentials present on this
                    // authenticator and bound to the specified rpId.
                    var ctx_and_mac: ?[]const u8 = null;
                    if (gap.@"3") |creds| {
                        for (creds) |cred| {
                            if (cred.id.len < crypt.cred_id_len) continue;

                            if (crypt.verifyCredId(secret_data.?.master_secret, cred.id, gap.@"1")) {
                                ctx_and_mac = cred.id[0..];
                                break;
                            }
                        }
                    }

                    // 2. If pinAuth parameter is present and pinProtocol is 1,
                    // verify it by matching it against first 16 bytes of
                    // HMAC-SHA-256 of clientDataHash parameter using pinToken:
                    // HMAC-SHA-256(pinToken, clientDataHash).
                    //   - If the verification succeeds, set the "uv" bit to 1
                    //     in the response.
                    //   - If the verification fails, return
                    //     CTAP2_ERR_PIN_AUTH_INVALID error.
                    // TODO: implement

                    // 3. If pinAuth parameter is present and the pinProtocol is
                    // not supported, return CTAP2_ERR_PIN_AUTH_INVALID.
                    if (gap.@"6" != null) {
                        // for now pinAuth is not supported
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_pin_auth_invalid);
                        return res.toOwnedSlice();
                    }

                    // 4. If pinAuth parameter is not present and clientPin has
                    // been set on the authenticator, set the "uv" bit to 0 in
                    // the response.
                    // TODO: implement

                    // 5. If the options parameter is present, process all the
                    // options. If the option is known but not supported,
                    // terminate this procedure and return
                    // CTAP2_ERR_UNSUPPORTED_OPTION. If the option is known but
                    // not valid for this command, terminate this procedure and
                    // return CTAP2_ERR_INVALID_OPTION. Ignore any options that
                    // are not understood. Note that because this specification
                    // defines normative behaviors for them, all authenticators
                    // MUST understand the "rk", "up", and "uv" options.
                    if (gap.@"5") |opt| {
                        if (opt.uv or !opt.up) { // currently no uv supported
                            res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_invalid_option);
                            return res.toOwnedSlice();
                        }
                    }

                    // 7. Collect user consent if required. This step MUST
                    // happen before the following steps due to privacy reasons
                    // (i.e., authenticator cannot disclose existence of a
                    // credential until the user interacted with the device):
                    if (!requestPermission(null, null)) {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_operation_denied);
                        return res.toOwnedSlice();
                    }

                    // 8. If no credentials were located in step 1, return
                    // CTAP2_ERR_NO_CREDENTIALS.
                    if (ctx_and_mac == null) {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_no_credentials);
                        return res.toOwnedSlice();
                    }

                    // 10. If authenticator does not have a display:
                    //   - Remember the authenticatorGetAssertion parameters.
                    //   - Create a credential counter(credentialCounter) and
                    //     set it 1. This counter signifies how many credentials
                    //     are sent to the platform by the authenticator.
                    //   - Start a timer. This is used during
                    //     authenticatorGetNextAssertion command. This step is
                    //     optional if transport is done over NFC.
                    //   - Update the response to include the first credential’s
                    //     publicKeyCredentialUserEntity information and
                    //     numberOfCredentials. User identifiable information
                    //     (name, DisplayName, icon) inside
                    //     publicKeyCredentialUserEntity MUST not be returned if
                    //     user verification is not done by the authenticator.
                    // TODO: implement???

                    // 11. If authenticator has a display:
                    //   - Display all these credentials to the user, using
                    //     their friendly name along with other stored account
                    //     information.
                    //   - Also, display the rpId of the requester (specified
                    //     in the request) and ask the user to select a
                    //     credential.
                    //   - If the user declines to select a credential or takes
                    //     too long (as determined by the authenticator),
                    //     terminate this procedure and return the
                    //     CTAP2_ERR_OPERATION_DENIED error.
                    // TODO: implement???

                    // Return signature
                    var ad = dobj.AuthData{
                        .rp_id_hash = undefined,
                        .flags = dobj.Flags{
                            .up = 1,
                            .rfu1 = 0,
                            .uv = 0,
                            .rfu2 = 0,
                            .at = 0,
                            .ed = 0,
                        },
                        .sign_count = secret_data.?.sign_ctr,
                        // attestedCredentialData are excluded
                    };
                    secret_data.?.sign_ctr += 1;
                    std.crypto.hash.sha2.Sha256.hash(gap.@"1", &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    // 12. Sign the clientDataHash along with authData with the
                    // selected credential.
                    const kp = crypt.deriveKeyPair(secret_data.?.master_secret, ctx_and_mac.?[0..32].*) catch unreachable; // TODO: is it???

                    const sig = crypt.sign(kp, authData.items, gap.@"2") catch {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap1_err_other);
                        return res.toOwnedSlice();
                    };

                    var x: [crypt.der_len]u8 = undefined;
                    const gar = GetAssertionResponse{
                        .@"1" = dobj.PublicKeyCredentialDescriptor{
                            .type = "public-key",
                            .id = ctx_and_mac.?,
                        },
                        .@"2" = authData.items,
                        .@"3" = sig.toDer(&x),
                    };

                    cbor.stringify(gar, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(dobj.StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_get_info => {
                    cbor.stringify(self.info, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(dobj.StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_client_pin => {
                    const cpp = cbor.parse(ClientPinParam, try cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => dobj.StatusCodes.ctap2_err_missing_parameter,
                            else => dobj.StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    defer cpp.deinit(allocator);

                    // Handle one of the subcommands.
                    var cpr: ?ClientPinResponse = null;
                    switch (cpp.@"2") {
                        .getRetries => {
                            cpr = .{
                                .@"3" = data.meta.pin_retries,
                            };
                        },
                        .getKeyAgreement => {
                            // Validate arguments
                            // +++++++++++++++++++
                            // return error if required parameter is not provided.
                            const protocol = if (cpp.@"1") |prot| prot else {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_missing_parameter);
                                return res.toOwnedSlice();
                            };
                            // return error if authenticator doesn't support the selected protocol.
                            if (protocol != .v2) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap1_err_invalid_parameter);
                                return res.toOwnedSlice();
                            }

                            // Create response
                            // +++++++++++++++++
                            cpr = .{
                                .@"1" = S.state.getPublicKey(),
                            };
                        },
                        .setPIN => {},
                        .changePIN => {
                            // Return error if the authenticator does not receive the
                            // mandatory parameters for this command.
                            if (cpp.@"1" == null or cpp.@"3" == null or cpp.@"5" == null or
                                cpp.@"6" == null or cpp.@"4" == null)
                            {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_missing_parameter);
                                return res.toOwnedSlice();
                            }

                            // If pinUvAuthProtocol is not supported, return error.
                            if (cpp.@"1".? != .v2) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap1_err_invalid_parameter);
                                return res.toOwnedSlice();
                            }

                            // If the pinRetries counter is 0, return error.
                            const retries = data.meta.pin_retries;
                            if (retries <= 0) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_pin_blocked);
                                return res.toOwnedSlice();
                            }

                            // Obtain the shared secret
                            const shared_secret = S.state.ecdh(cpp.@"3".?) catch {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap1_err_invalid_parameter);
                                return res.toOwnedSlice();
                            };

                            // Verify the data (newPinEnc || pinHashEnc)
                            const new_pin_len = cpp.@"5".?.len;
                            var msg = try allocator.alloc(u8, new_pin_len + 16);
                            defer allocator.free(msg);
                            std.mem.copy(u8, msg[0..new_pin_len], cpp.@"5".?[0..]);
                            std.mem.copy(u8, msg[new_pin_len..], cpp.@"6".?[0..]);

                            const verified = PinUvAuthTokenState.verify(
                                shared_secret[0..32].*,
                                msg, // newPinEnc || pinHashEnc
                                cpp.@"4".?, // pinUvAuthParam
                            );
                            if (!verified) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_pin_auth_invalid);
                                return res.toOwnedSlice();
                            }

                            // decrement pin retries
                            data.meta.pin_retries = retries - 1;

                            // Decrypt pinHashEnc and match against stored pinHash
                            var pinHash1: [16]u8 = undefined;
                            PinUvAuthTokenState.decrypt(
                                shared_secret,
                                pinHash1[0..],
                                cpp.@"6".?[0..],
                            );
                            if (!std.mem.eql(u8, pinHash1[0..], secret_data.?.pin_hash[0..])) {
                                // The pin hashes don't match
                                S.state.regenerate(getBlock);

                                res.items[0] = if (data.meta.pin_retries == 0)
                                    @enumToInt(dobj.StatusCodes.ctap2_err_pin_blocked)
                                    // TODO: reset authenticator -> DOOMSDAY
                                else
                                    @enumToInt(dobj.StatusCodes.ctap2_err_pin_invalid);
                                return res.toOwnedSlice();
                            }

                            // Set the pinRetries to maximum
                            data.meta.pin_retries = 8;

                            // Decrypt new pin
                            var paddedNewPin: [64]u8 = undefined;
                            PinUvAuthTokenState.decrypt(
                                shared_secret,
                                paddedNewPin[0..],
                                cpp.@"5".?[0..],
                            );
                            var pnp_end: usize = 0;
                            while (paddedNewPin[pnp_end] != 0 and pnp_end < 64) : (pnp_end += 1) {}
                            const newPin = paddedNewPin[0..pnp_end];
                            if (newPin.len < commands.client_pin.minimum_pin_length) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_pin_policy_violation);
                                return res.toOwnedSlice();
                            }

                            // TODO: support forcePINChange
                            // TODO: support 15.
                            // TODO: support 16.

                            // Store new pin
                            secret_data.?.pin_hash = crypt.pinHash(newPin);

                            // Invalidate pinUvAuthTokens
                            S.state.resetPinUvAuthToken(getBlock);
                        },
                        .getPinUvAuthTokenUsingPin => {
                            // Return error if the authenticator does not receive the
                            // mandatory parameters for this command.
                            if (cpp.@"1" == null or cpp.@"3" == null or cpp.@"5" == null or cpp.@"9" == null)
                            {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap2_err_missing_parameter);
                                return res.toOwnedSlice();
                            }

                            // If pinUvAuthProtocol is not supported or the permissions are 0, 
                            // return error.
                            if (cpp.@"1".? != .v2 or cpp.@"9".? == 0) {
                                res.items[0] =
                                    @enumToInt(dobj.StatusCodes.ctap1_err_invalid_parameter);
                                return res.toOwnedSlice();
                            }

                        },
                        else => {},
                    }

                    if (cpr) |resp| {
                        cbor.stringify(resp, .{}, response) catch |err| {
                            res.items[0] = @enumToInt(dobj.StatusCodes.fromError(err));
                            return res.toOwnedSlice();
                        };
                    }
                },
                .authenticator_reset => {
                    // Resetting an authenticator is a destructive operation!

                    // Request permission from the user
                    if (!requestPermission(null, null)) {
                        res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_operation_denied);
                        return res.toOwnedSlice();
                    }

                    reset(allocator, data.meta.nonce_ctr);
                    write_back = false;
                },
                .authenticator_get_next_assertion => {},
                .authenticator_vendor_first => {},
                .authenticator_vendor_last => {},
            }

            return res.toOwnedSlice();
        }
    };
}

const tests = @import("tests.zig");

test "main" {
    _ = tests;
    _ = dobj;
    _ = crypt;
    _ = commands;
    _ = ctaphid;
    _ = data_module;
}
