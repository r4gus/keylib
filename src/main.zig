/// Client to Authenticator (CTAP) library
const std = @import("std");

pub const crypt = @import("crypto.zig");
const EcdsaPubKey = crypt.EcdsaPubKey;
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
/// Master secret length
pub const ms_length = Hmac.mac_length;
pub const Ecdsa = crypt.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;
pub const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const ECDH = std.crypto.dh.X25519;

const cbor = @import("zbor");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DataItem = cbor.DataItem;
const Pair = cbor.Pair;

const status = @import("status.zig");
pub const StatusCodes = status.StatusCodes;
const errors = @import("error.zig");
pub const Errors = errors.ErrorCodes;
const commands = @import("commands.zig");
pub const Commands = commands.Commands;
const getCommand = commands.getCommand;
const MakeCredentialParam = commands.make_credential.MakeCredentialParam;
const GetAssertionParam = commands.get_assertion.GetAssertionParam;
const GetAssertionResponse = commands.get_assertion.GetAssertionResponse;
const version = @import("version.zig");
pub const Versions = version.Versions;
const extension = @import("extensions.zig");
pub const Extensions = extension.Extensions;
const option = @import("options.zig");
pub const Options = option.Options;
const pinprot = @import("pinprot.zig");
pub const PinProtocols = pinprot.PinProtocols;
const attestation_object = @import("attestation_object.zig");
const AttestedCredentialData = attestation_object.AttestedCredentialData;
const AuthData = attestation_object.AuthData;
const Flags = attestation_object.Flags;
const AttestationObject = attestation_object.AttestationObject;
const Fmt = attestation_object.Fmt;
const AttStmt = attestation_object.AttStmt;
pub const User = @import("user.zig");
pub const RelyingParty = @import("rp.zig");
const client_pin = @import("client_pin.zig");
const ClientPinParam = client_pin.ClientPinParam;
const ClientPinResponse = client_pin.ClientPinResponse;

/// General properties of a given authenticator.
pub const Info = struct {
    /// versions: List of supported versions.
    @"1_t": []const Versions,
    /// extensions: List of supported extensions.
    @"2_t": ?[]const Extensions,
    /// aaguid: The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
    /// indicating the type of the authenticator. Authenticators with the
    /// same capabilities and firmware, can share the same AAGUID.
    @"3_b": [16]u8,
    /// optoins: Supported options.
    @"4": ?Options,
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

const PinConf = struct {
    /// A ECDH X25519 key denoted by (a, aG) where "a" denotes
    /// the private key and "aG" denotes the public key. A new
    /// key is generated on each powerup.
    authenticator_key_agreement_key: ECDH.KeyPair,
    /// A random integer of length which is multiple of 16 bytes
    /// (AES block length).
    pin_token: [32]u8,
};

pub fn Auth(comptime impl: type) type {
    return struct {
        const Self = @This();

        /// General properties of the given authenticator.
        info: Info,
        /// Attestation type to be used for attestation.
        attestation_type: AttestationType,
        /// PIN configuration generated during initialization.
        pin_conf: PinConf,

        /// Default initialization without extensions.
        pub fn initDefault(versions: []const Versions, aaguid: [16]u8) Self {
            var seed: [ECDH.seed_length]u8 = undefined;
            var token: [32]u8 = undefined;
            crypto.getBlock(seed[0..]);
            crypto.getBlock(token[0..]);

            return @This(){
                .info = Info{
                    .@"1_t" = versions,
                    .@"2_t" = null,
                    .@"3_b" = aaguid,
                    .@"4" = Options{}, // default options
                    .@"5" = null,
                    .@"6" = null,
                },
                .attestation_type = AttestationType{},
                .pin_conf = .{
                    .authenticator_key_agreement_key = ECDH.KeyPair.create(seed) catch unreachable,
                    .pin_token = token,
                },
            };
        }

        /// This function asks the user in some way for permission,
        /// e.g. button press, touch, key press.
        ///
        /// It returns `true` if permission has been granted, `false`
        /// otherwise (e.g. timeout).
        pub fn requestPermission(user: ?*const User, rp: ?*const RelyingParty) bool {
            return impl.requestPermission(user, rp);
        }

        /// Return the (updated) signature count for the given credential id.
        /// This can either be a distinct counter for each credential
        /// or a global counter for all.
        pub fn getSignCount(cred_id: []const u8) u32 {
            return impl.getSignCount(cred_id);
        }

        /// Retries count is the number of attempts remaining before lockout.
        pub fn getRetries() u8 {
            return impl.getRetries();
        }

        pub const crypto = struct {
            const key_len: usize = 32;
            const ctx_len: usize = 32;

            pub const KeyContext = struct {
                /// Context which serves as KEYID and is stored
                /// by the RP.
                ctx: [ctx_len]u8,
                /// Key-Pair derived from the context and the
                /// master secret. The private key must be kept
                /// secret. The public key is stored by the
                /// RP.
                key_pair: KeyPair,
            };

            /// Get a 32 bit random number.
            pub fn rand() u32 {
                return impl.rand();
            }

            /// Fill the given slice with random data.
            pub fn getBlock(buffer: []u8) void {
                var r: u32 = undefined;

                var i: usize = 0;
                while (i < buffer.len) : (i += 1) {
                    if (i % 4 == 0) {
                        // Get a fresh 32 bit integer every 4th iteration.
                        r = rand();
                    }

                    // The shift value is always between 0 and 24, i.e. int cast will always succeed.
                    buffer[i] = @intCast(u8, (r >> @intCast(u5, (8 * (i % 4)))) & 0xff);
                }
            }

            /// Get the stored master secret.
            ///
            /// The master secret must be created on first boot, i.e.
            /// one can expect the master secret to be available at
            /// any time.
            pub fn getMs() [ms_length]u8 {
                // Create a more uniformly unbiased and higher entropy,
                // from the RANDOMLY GENERATED master secret.
                const ikm = impl.getMs();
                const salt = "CANDYSTICK";
                return Hkdf.extract(salt, &ikm);
            }

            /// Create and store a new master secret.
            ///
            /// This function has to be called once on first boot
            /// to create the secret. The master secret must not
            /// change between power cycles. Changing the secret
            /// means invalidating all generated key pairs, which
            /// is equivalent to a reset.
            pub fn createMs() void {
                impl.createMs();
            }

            /// Derive a (deterministic) sub-key for message authentication codes.
            pub fn getMacKey() [key_len]u8 {
                var mac_key: [key_len]u8 = undefined;
                Hkdf.expand(mac_key[0..], "MACKEY", getMs());
                return mac_key;
            }

            /// Create a new key-pair.
            pub fn createKeyPair() !KeyContext {
                // Get new random context for new key pair
                var ctx: [ctx_len]u8 = undefined;
                getBlock(ctx[0..]);

                // Derive subkey (seed) from master secret and ctx
                var seed: [key_len]u8 = undefined;
                Hkdf.expand(seed[0..], ctx[0..], getMs());

                // Create a new (deterministic) key pair
                const kc = KeyContext{
                    .ctx = ctx,
                    .key_pair = try KeyPair.create(seed),
                };

                return kc;
            }

            /// Derive a (deterministic) key-pair from a given context `ctx`.
            ///
            /// Note: If you change the master secret used during `createKeyPair`
            /// you won't be able to derive the correct key-pair from the given context.
            pub fn deriveKeyPair(ctx: [ctx_len]u8) !KeyPair {
                var seed: [key_len]u8 = undefined;
                Hkdf.expand(seed[0..], ctx[0..], getMs());
                return try KeyPair.create(seed);
            }
        };

        /// Main handler function, that takes a command and returns a response.
        pub fn handle(self: *const Self, allocator: Allocator, command: []const u8) ![]u8 {
            // The response message.
            // For encodings see: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses
            var res = std.ArrayList(u8).init(allocator);
            var response = res.writer();
            try response.writeByte(0x00); // just overwrite if neccessary

            const cmdnr = getCommand(command) catch |err| {
                // On error, respond with a error code and return.
                try response.writeByte(@enumToInt(StatusCodes.fromError(err)));
                return res.toOwnedSlice();
            };

            switch (cmdnr) {
                .authenticator_make_credential => {
                    // TODO: Check exclude list... just ignore it for now
                    // {1: h'C03991AC3DFF02BA1E520FC59B2D34774A641A4C425ABD313D931061FFBD1A5C', 2: {"id": "localhost", "name": "sweet home localhost"}, 3: {"id": h'781C7860AD88D26332622AF1745DEDB2E7A42B44892939C5566401270DBBC449', "name": "john smith", "displayName": "jsmith"}, 4: [{"alg": -7, "type": "public-key"}]}
                    const mcp = cbor.parse(MakeCredentialParam, cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => StatusCodes.ctap2_err_missing_parameter,
                            else => StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    defer mcp.deinit(allocator);

                    // 1. If the excludeList parameter is present and contains a
                    // credential ID that is present on this authenticator and
                    // bound to the specified rpId, wait for user presence, then
                    // terminate this procedure and return error code
                    // CTAP2_ERR_CREDENTIAL_EXCLUDED.
                    // TODO: check

                    // 2. If the pubKeyCredParams parameter does not contain a valid
                    // COSEAlgorithmIdentifier value that is supported by the
                    // authenticator, terminate this procedure and return error code
                    // CTAP2_ERR_UNSUPPORTED_ALGORITHM.
                    var valid_param: bool = false;
                    for (mcp.@"4") |param| {
                        if (param.alg == -7) { // ES256
                            valid_param = true;
                            break;
                        }
                    }
                    if (!valid_param) {
                        res.items[0] = @enumToInt(StatusCodes.ctap2_err_unsupported_algorithm);
                        return res.toOwnedSlice();
                    }

                    // 3. If the options parameter is present, process all the options.
                    // If the option is known but not supported, terminate this procedure
                    // and return CTAP2_ERR_UNSUPPORTED_OPTION. If the option is known
                    // but not valid for this command, terminate this procedure and
                    // return CTAP2_ERR_INVALID_OPTION. Ignore any options that are not
                    // understood. Note that because this specification defines normative
                    // behaviors for them, all authenticators MUST understand the "rk",
                    // "up", and "uv" options.
                    if (mcp.@"7") |options| {
                        if (options.rk) {
                            // we let the RP store the context for each credential.
                            res.items[0] = @enumToInt(StatusCodes.ctap2_err_unsupported_option);
                            return res.toOwnedSlice();
                        }
                        if (options.uv) {
                            // TODO: user must provide two functions:
                            //  1. verificationAvailable() -> bool
                            //  2. verify() -> bool
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

                    // 8. If the authenticator has a display, show the items contained
                    // within the user and rp parameter structures to the user.
                    // Alternatively, request user interaction in an
                    // authenticator-specific way (e.g., flash the LED light).
                    // Request permission to create a credential. If the user declines
                    // permission, return the CTAP2_ERR_OPERATION_DENIED error.
                    if (!requestPermission(&mcp.@"3", &mcp.@"2")) {
                        res.items[0] = @enumToInt(StatusCodes.ctap2_err_operation_denied);
                        return res.toOwnedSlice();
                    }

                    // 9. Generate a new credential key pair for the algorithm specified.
                    const context = crypto.createKeyPair() catch {
                        res.items[0] = @enumToInt(StatusCodes.ctap1_err_other);
                        return res.toOwnedSlice();
                    };

                    // 10. If "rk" in options parameter is set to true.
                    //     * If a credential for the same RP ID and account ID already
                    //       exists on the authenticator, overwrite that credential.
                    //     * Store the user parameter along the newly-created key pair.
                    //     * If authenticator does not have enough internal storage to
                    //       persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
                    // TODO: Resident key support currently not planned

                    // credId consists of the context used to derive the
                    // private key and a MAC of the ctx and the rpId. This
                    // is how we can make sure that the ctx or rpId havent
                    // been tempered with.
                    var cred_id: [crypto.ctx_len + Hmac.mac_length]u8 = undefined;
                    std.mem.copy(u8, cred_id[0..32], &context.ctx);
                    const key = crypto.getMacKey();
                    var ctx = Hmac.init(&key);
                    ctx.update(&context.ctx);
                    ctx.update(mcp.@"2".id);
                    ctx.final(cred_id[32..]);

                    // 11. Generate an attestation statement for the newly-created
                    // key using clientDataHash.
                    const acd = AttestedCredentialData{
                        .aaguid = self.info.@"3_b",
                        .credential_length = crypto.ctx_len + Hmac.mac_length,
                        // context is used as id to later retrieve actual key using
                        // the master secret.
                        .credential_id = &cred_id,
                        .credential_public_key = EcdsaPubKey.new(context.key_pair.public_key),
                    };

                    var ad = AuthData{
                        .rp_id_hash = undefined,
                        .flags = Flags{
                            .up = 1,
                            .rfu1 = 0,
                            .uv = 0,
                            .rfu2 = 0,
                            .at = 1,
                            .ed = 0,
                        },
                        .sign_count = getSignCount(cred_id[0..]),
                        .attested_credential_data = acd,
                    };
                    // Calculate the SHA-256 hash of the rpId (base url).
                    std.crypto.hash.sha2.Sha256.hash(mcp.@"2".id, &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    // Create attestation statement
                    var stmt: ?AttStmt = null;
                    if (self.attestation_type.att_type == .self) {
                        var st = context.key_pair.signer(null) catch {
                            res.items[0] = @enumToInt(StatusCodes.ctap1_err_other);
                            return res.toOwnedSlice();
                        };
                        st.update(authData.items);
                        st.update(mcp.@"1"); // clientDataHash
                        const sig = st.finalize() catch {
                            res.items[0] = @enumToInt(StatusCodes.ctap1_err_other);
                            return res.toOwnedSlice();
                        };

                        var x: [Ecdsa.Signature.der_encoded_max_length]u8 = undefined;
                        stmt = AttStmt{ .@"packed" = .{
                            .alg_b = crypt.CoseId.ES256,
                            .sig_b = sig.toDer(&x),
                        } };
                    } else {
                        stmt = AttStmt{ .none = .{} };
                    }

                    const ao = AttestationObject{
                        .@"1" = Fmt.@"packed",
                        .@"2_b" = authData.items,
                        .@"3" = stmt.?,
                    };

                    cbor.stringify(ao, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_get_assertion => {
                    const gap = cbor.parse(GetAssertionParam, cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => StatusCodes.ctap2_err_missing_parameter,
                            else => StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    defer gap.deinit(allocator);

                    var ctx_and_mac: ?[]const u8 = null;
                    // 1. locate all denoted credentials present on this
                    // authenticator and bound to the specified rpId.
                    if (gap.@"3") |creds| {
                        for (creds) |cred| {
                            if (cred.id.len < crypto.ctx_len + Hmac.mac_length) {
                                continue;
                            }

                            // Recalculate the hash
                            var mac: [Hmac.mac_length]u8 = undefined;
                            const key = crypto.getMacKey();
                            var hctx = Hmac.init(&key);
                            hctx.update(cred.id[0..32]); // ctx
                            hctx.update(gap.@"1"); // rpId
                            hctx.final(mac[0..]);

                            // Compare the received hash to the one just
                            // calculated.
                            if (std.mem.eql(u8, cred.id[32..], mac[0..])) {
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
                        res.items[0] = @enumToInt(StatusCodes.ctap2_err_pin_auth_invalid);
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
                            res.items[0] = @enumToInt(StatusCodes.ctap2_err_invalid_option);
                            return res.toOwnedSlice();
                        }
                    }

                    // 7. Collect user consent if required. This step MUST
                    // happen before the following steps due to privacy reasons
                    // (i.e., authenticator cannot disclose existence of a
                    // credential until the user interacted with the device):
                    if (!requestPermission(null, null)) {
                        res.items[0] = @enumToInt(StatusCodes.ctap2_err_operation_denied);
                        return res.toOwnedSlice();
                    }

                    // 8. If no credentials were located in step 1, return
                    // CTAP2_ERR_NO_CREDENTIALS.
                    if (ctx_and_mac == null) {
                        res.items[0] = @enumToInt(StatusCodes.ctap2_err_no_credentials);
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
                    var ad = AuthData{
                        .rp_id_hash = undefined,
                        .flags = Flags{
                            .up = 1,
                            .rfu1 = 0,
                            .uv = 0,
                            .rfu2 = 0,
                            .at = 1,
                            .ed = 0,
                        },
                        .sign_count = getSignCount(ctx_and_mac.?),
                        // attestedCredentialData are excluded
                    };
                    std.crypto.hash.sha2.Sha256.hash(gap.@"1", &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    // 12. Sign the clientDataHash along with authData with the
                    // selected credential.
                    const kp = crypto.deriveKeyPair(ctx_and_mac.?[0..32].*) catch unreachable; // TODO: is it???
                    var st = kp.signer(null) catch {
                        res.items[0] = @enumToInt(StatusCodes.ctap1_err_other);
                        return res.toOwnedSlice();
                    };
                    st.update(authData.items); // authData
                    st.update(gap.@"2_b"); // clientDataHash
                    const sig = st.finalize() catch {
                        res.items[0] = @enumToInt(StatusCodes.ctap1_err_other);
                        return res.toOwnedSlice();
                    };

                    var x: [Ecdsa.Signature.der_encoded_max_length]u8 = undefined;
                    const gar = GetAssertionResponse{
                        .@"2_b" = authData.items,
                        .@"3_b" = sig.toDer(&x),
                    };

                    cbor.stringify(gar, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_get_info => {
                    cbor.stringify(self.info, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_client_pin => {
                    const cpp = cbor.parse(ClientPinParam, cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
                        const x = switch (err) {
                            error.MissingField => StatusCodes.ctap2_err_missing_parameter,
                            else => StatusCodes.ctap2_err_invalid_cbor,
                        };
                        res.items[0] = @enumToInt(x);
                        return res.toOwnedSlice();
                    };
                    // TODO: defer mcp.deinit(allocator);

                    var cpr: ?ClientPinResponse = null;
                    switch (cpp.@"2") {
                        .getRetries => {
                            cpr = .{
                                .@"3" = getRetries(),
                            };
                        },
                        else => {},
                    }

                    if (cpr) |resp| {
                        cbor.stringify(resp, .{}, response) catch |err| {
                            res.items[0] = @enumToInt(StatusCodes.fromError(err));
                            return res.toOwnedSlice();
                        };
                    }
                },
                .authenticator_reset => {},
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
    _ = attestation_object;
    _ = crypt;
    _ = commands;
}
