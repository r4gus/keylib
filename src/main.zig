/// Client to Authenticator (CTAP) library
const std = @import("std");
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
pub const ms_length = Hmac.mac_length;
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;
pub const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

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
pub const crypt = @import("crypto.zig");
const EcdsaPubKey = crypt.EcdsaPubKey;
pub const User = @import("user.zig");
pub const RelyingParty = @import("rp.zig");

pub fn Auth(comptime impl: type) type {
    return struct {
        const Self = @This();

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

        /// Default initialization without extensions.
        pub fn initDefault(versions: []const Versions, aaguid: [16]u8) Self {
            return @This(){
                .@"1_t" = versions,
                .@"2_t" = null,
                .@"3_b" = aaguid,
                .@"4" = Options.default(),
                .@"5" = null,
                .@"6" = null,
            };
        }

        /// This function asks the user in some way for permission,
        /// e.g. button press, touch, key press.
        ///
        /// It returns `true` if permission has been granted, `false`
        /// otherwise (e.g. timeout).
        pub fn requestPermission(user: *const User, rp: *const RelyingParty) bool {
            return impl.requestPermission(user, rp);
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
                return impl.getMs();
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

                    // 11. Generate an attestation statement for the newly-created
                    // key using clientDataHash.
                    const acd = AttestedCredentialData{
                        .aaguid = self.@"3_b",
                        .credential_length = crypto.ctx_len,
                        // context is used as id to later retrieve actual key using
                        // the master secret.
                        .credential_id = &context.ctx,
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
                        .sign_count = 0, // TODO: replace with function call
                        .attested_credential_data = acd,
                        .extensions = "",
                    };
                    std.crypto.hash.sha2.Sha256.hash(mcp.@"2".id, &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    const ao = AttestationObject{
                        .@"1" = Fmt.@"packed",
                        .@"2_b" = authData.items,
                        .@"3" = AttStmt{ .none = .{} },
                    };

                    cbor.stringify(ao, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_get_assertion => {},
                .authenticator_get_info => {
                    cbor.stringify(self, .{}, response) catch |err| {
                        res.items[0] = @enumToInt(StatusCodes.fromError(err));
                        return res.toOwnedSlice();
                    };
                },
                .authenticator_client_pin => {},
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
