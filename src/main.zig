/// Client to Authenticator (CTAP) library
const std = @import("std");

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
const PinConf = commands.client_pin.PinConf;

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

        pub const Data = struct {
            d: [data_len]u8 = undefined,

            pub fn load() @This() {
                return @This(){
                    .d = impl.load(),
                };
            }

            pub fn store(self: *@This()) void {
                impl.store(self.d);
            }

            /// Tells if the given data structure is valid or not.
            pub fn isValid(self: *const @This()) bool {
                return self.d[0] == 0xF1;
            }

            /// Tells if the given data structure is valid or not.
            pub fn setValid(self: *@This()) void {
                self.d[0] = 0xF1;
            }

            pub fn getMs(self: *const @This()) [ms_length]u8 {
                return self.d[1 .. ms_length + 1].*;
            }

            pub fn setMs(self: *@This(), data: [ms_length]u8) void {
                std.mem.copy(u8, self.d[1 .. ms_length + 1], data[0..]);
            }

            pub fn getPin(self: *const @This()) [pin_len]u8 {
                return self.d[ms_length + 1 .. ms_length + 1 + pin_len].*;
            }

            pub fn setPin(self: *@This(), data: [pin_len]u8) void {
                std.mem.copy(u8, self.d[ms_length + 1 .. ms_length + 1 + pin_len], data[0..]);
            }

            pub fn isPinSet(self: *const @This()) bool {
                const p = self.getPin();
                var i: usize = 0;
                while (i < pin_len) : (i += 1) {
                    if (p[i] != 0) return true;
                }
                return false;
            }

            pub fn getSignCtr(self: *@This()) u32 {
                const offset: usize = 1 + ms_length + pin_len;
                const x: u32 = std.mem.readIntSliceLittle(u32, self.d[offset .. offset + 4]);
                std.mem.writeIntSliceLittle(u32, self.d[offset .. offset + 4], x + 1);
                return x;
            }

            pub fn setSignCtr(self: *@This(), data: u32) void {
                const offset: usize = 1 + ms_length + pin_len;
                std.mem.writeIntSliceLittle(u32, self.d[offset .. offset + 4], data);
            }

            pub fn getRetries(self: *const @This()) u8 {
                const offset: usize = 1 + ms_length + pin_len + 4;
                return self.d[offset];
            }

            pub fn setRetries(self: *@This(), data: u8) void {
                const offset: usize = 1 + ms_length + pin_len + 4;
                self.d[offset] = data;
            }
        };

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

        pub fn initData(self: *const Self) void {
            _ = self;
            var data = Data.load();

            // Do nothing if data has already been initialized.
            if (data.isValid()) return;

            // Create a more uniformly unbiased and higher entropy,
            // from the RANDOMLY GENERATED byte string.
            var ikm: [32]u8 = undefined;
            getBlock(ikm[0..]);
            const salt = "F1D0";
            const ms = Hkdf.extract(salt, &ikm);

            data.setMs(ms);
            data.setPin("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*);
            data.setSignCtr(0);
            data.setRetries(8);
            data.setValid();
            data.store();
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

            var data = Data.load();
            defer data.store(); // write changes back to memory

            switch (cmdnr) {
                .authenticator_make_credential => {
                    // TODO: Check exclude list... just ignore it for now
                    const mcp = cbor.parse(MakeCredentialParam, try cbor.DataItem.new(command[1..]), .{ .allocator = allocator }) catch |err| {
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

                    // Generate a new credential key pair for the algorithm specified.
                    const context = crypt.newContext(getBlock);
                    const key_pair = crypt.deriveKeyPair(data.getMs(), context) catch unreachable;

                    // 10. If "rk" in options parameter is set to true.
                    //     * If a credential for the same RP ID and account ID already
                    //       exists on the authenticator, overwrite that credential.
                    //     * Store the user parameter along the newly-created key pair.
                    //     * If authenticator does not have enough internal storage to
                    //       persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
                    // TODO: Resident key support currently not planned

                    // Create a new credential id
                    const cred_id = crypt.makeCredId(data.getMs(), &context, mcp.@"2".id);

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
                        .sign_count = data.getSignCtr(),
                        .attested_credential_data = acd,
                    };
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
                            .alg = cose.Algorithm.Es256,
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

                            if (crypt.verifyCredId(data.getMs(), cred.id, gap.@"1")) {
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
                        .sign_count = data.getSignCtr(),
                        // attestedCredentialData are excluded
                    };
                    std.crypto.hash.sha2.Sha256.hash(gap.@"1", &ad.rp_id_hash, .{});
                    var authData = std.ArrayList(u8).init(allocator);
                    defer authData.deinit();
                    try ad.encode(authData.writer());

                    // 12. Sign the clientDataHash along with authData with the
                    // selected credential.
                    const kp = crypt.deriveKeyPair(data.getMs(), ctx_and_mac.?[0..32].*) catch unreachable; // TODO: is it???

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
                    const PC = struct {
                        var conf: ?PinConf = null;
                    };

                    // Crete configuration only if a PIN command is actually issued.
                    if (PC.conf == null) {
                        PC.conf = commands.client_pin.makeConfig(getBlock) catch {
                            res.items[0] = @enumToInt(dobj.StatusCodes.ctap1_err_other);
                            return res.toOwnedSlice();
                        };
                    }

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
                                .@"3" = data.getRetries(),
                            };
                        },
                        .getKeyAgreement => {
                            // Authenticator responds back with public key of
                            // authenticatorKeyAgreementKey, "aG".
                            cpr = .{
                                .@"1" = cose.Key.fromP256Pub(
                                    .EcdhEsHkdf256,
                                    PC.conf.?.authenticator_key_agreement_key,
                                ),
                            };
                        },
                        .setPIN => {
                            // keyAgreement, pinAuth and newPinEnc are mandatory for this command.
                            if (cpp.@"3" == null or cpp.@"4" == null or cpp.@"5" == null) {
                                res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_missing_parameter);
                                return res.toOwnedSlice();
                            }

                            if (data.isPinSet()) {
                                res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_pin_auth_invalid);
                                return res.toOwnedSlice();
                            }

                            // Generate shared secret
                            const deG = EcdhP256.scalarmultXY(PC.conf.?.authenticator_key_agreement_key.secret_key, cpp.@"3".?.P256.@"-2", cpp.@"3".?.P256.@"-3") catch unreachable;
                            var shared_secret: [Sha256.digest_length]u8 = undefined;
                            // shared = SHA-256((deG).x)
                            Sha256.hash(deG.toUncompressedSec1()[1..33], &shared_secret, .{});

                            // Verify pinAuth
                            var auth_pin_auth: [Hmac.mac_length]u8 = undefined;
                            Hmac.create(&auth_pin_auth, cpp.@"5".?, shared_secret[0..]);
                            // Only the first 16 bytes are compared
                            if (!std.mem.eql(u8, auth_pin_auth[0..16], cpp.@"4".?[0..])) {
                                res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_pin_auth_invalid);
                                return res.toOwnedSlice();
                            }

                            // Decrypt the encrypted new pin using AES-256-CBC with IV=0
                            // i.e. the first block doesnt have to be XORed. The encrypted
                            // pin should be at least 64 bytes (CTAP2 docs)!
                            var new_pin: [64]u8 = undefined;
                            var i: usize = 0;
                            var ctx = Aes256.initDec(shared_secret);
                            ctx.decrypt(new_pin[0..16], cpp.@"5".?[0..16]);
                            ctx.decrypt(new_pin[16..32], cpp.@"5".?[16..32]);
                            while (i < 16) : (i += 1) new_pin[i + 16] ^= new_pin[i];
                            ctx.decrypt(new_pin[32..48], cpp.@"5".?[32..48]);
                            while (i < 32) : (i += 1) new_pin[i + 16] ^= new_pin[i];
                            ctx.decrypt(new_pin[48..64], cpp.@"5".?[48..64]);
                            while (i < 48) : (i += 1) new_pin[i + 16] ^= new_pin[i];
                            // Determine the length of the pin.
                            i = 0;
                            while (i < 64) : (i += 1) if (new_pin[i] == 0) break;

                            if (i < commands.client_pin.minimum_pin_length) {
                                res.items[0] = @enumToInt(dobj.StatusCodes.ctap2_err_pin_policy_violation);
                                return res.toOwnedSlice();
                            }

                            // Set the new PIN hash
                            var new_pin_hash: [Sha256.digest_length]u8 = undefined;
                            Sha256.hash(new_pin[0..i], &new_pin_hash, .{});
                            data.setPin(new_pin_hash[0..16].*);
                        },
                        .changePIN => {},
                        .getPINToken => {},
                        else => {},
                    }

                    if (cpr) |resp| {
                        cbor.stringify(resp, .{}, response) catch |err| {
                            res.items[0] = @enumToInt(dobj.StatusCodes.fromError(err));
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
    _ = dobj;
    _ = crypt;
    _ = commands;
}
