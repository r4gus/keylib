const builtin = @import("builtin");
const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;

/// ECDSA over P-256 with SHA-256.
pub const EcdsaP256Sha256 = Ecdsa(crypto.ecc.P256, crypto.hash.sha2.Sha256);

/// Elliptic Curve Digital Signature Algorithm (ECDSA).
pub fn Ecdsa(comptime Curve: type, comptime Hash: type) type {
    const Hmac = crypto.auth.hmac.Hmac(Hash);

    return struct {
        /// Length (in bytes) of optional random bytes, for non-deterministic signatures.
        pub const noise_length = Curve.scalar.encoded_length;

        /// An ECDSA secret key.
        pub const SecretKey = struct {
            /// Length (in bytes) of a raw secret key.
            pub const encoded_length = Curve.scalar.encoded_length;

            bytes: Curve.scalar.CompressedScalar,

            pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
                return SecretKey{ .bytes = bytes };
            }

            pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
                return sk.bytes;
            }
        };

        /// An ECDSA public key.
        pub const PublicKey = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            p: Curve,

            /// Create a public key from a SEC-1 representation.
            pub fn fromSec1(sec1: []const u8) !PublicKey {
                return PublicKey{ .p = try Curve.fromSec1(sec1) };
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };

        /// An ECDSA signature.
        pub const Signature = struct {
            /// Length (in bytes) of a raw signature.
            pub const encoded_length = Curve.scalar.encoded_length * 2;
            /// Maximum length (in bytes) of a DER-encoded signature.
            pub const der_encoded_max_length = encoded_length + 2 + 2 * 3;

            /// The R component of an ECDSA signature.
            r: Curve.scalar.CompressedScalar,
            /// The S component of an ECDSA signature.
            s: Curve.scalar.CompressedScalar,

            /// Create a Verifier for incremental verification of a signature.
            pub fn verifier(self: Signature, public_key: PublicKey) (NonCanonicalError || EncodingError || IdentityElementError)!Verifier {
                return Verifier.init(self, public_key);
            }

            /// Verify the signature against a message and public key.
            /// Return IdentityElement or NonCanonical if the public key or signature are not in the expected range,
            /// or SignatureVerificationError if the signature is invalid for the given message and key.
            pub fn verify(self: Signature, msg: []const u8, public_key: PublicKey) (IdentityElementError || NonCanonicalError || SignatureVerificationError)!void {
                var st = try Verifier.init(self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature (r, s) in big-endian format.
            pub fn toBytes(self: Signature) [encoded_length]u8 {
                var bytes: [encoded_length]u8 = undefined;
                @memcpy(bytes[0 .. encoded_length / 2], &self.r);
                @memcpy(bytes[encoded_length / 2 ..], &self.s);
                return bytes;
            }

            /// Create a signature from a raw encoding of (r, s).
            /// ECDSA always assumes big-endian.
            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return Signature{
                    .r = bytes[0 .. encoded_length / 2].*,
                    .s = bytes[encoded_length / 2 ..].*,
                };
            }

            /// Encode the signature using the DER format.
            /// The maximum length of the DER encoding is der_encoded_max_length.
            /// The function returns a slice, that can be shorter than der_encoded_max_length.
            pub fn toDer(self: Signature, buf: *[der_encoded_max_length]u8) []u8 {
                var fb = io.fixedBufferStream(buf);
                const w = fb.writer();
                const r_len = @as(u8, @intCast(self.r.len + (self.r[0] >> 7)));
                const s_len = @as(u8, @intCast(self.s.len + (self.s[0] >> 7)));
                const seq_len = @as(u8, @intCast(2 + r_len + 2 + s_len));
                w.writeAll(&[_]u8{ 0x30, seq_len }) catch unreachable;
                w.writeAll(&[_]u8{ 0x02, r_len }) catch unreachable;
                if (self.r[0] >> 7 != 0) {
                    w.writeByte(0x00) catch unreachable;
                }
                w.writeAll(&self.r) catch unreachable;
                w.writeAll(&[_]u8{ 0x02, s_len }) catch unreachable;
                if (self.s[0] >> 7 != 0) {
                    w.writeByte(0x00) catch unreachable;
                }
                w.writeAll(&self.s) catch unreachable;
                return fb.getWritten();
            }

            // Read a DER-encoded integer.
            fn readDerInt(out: []u8, reader: anytype) EncodingError!void {
                var buf: [2]u8 = undefined;
                _ = reader.readNoEof(&buf) catch return error.InvalidEncoding;
                if (buf[0] != 0x02) return error.InvalidEncoding;
                var expected_len = @as(usize, buf[1]);
                if (expected_len == 0 or expected_len > 1 + out.len) return error.InvalidEncoding;
                var has_top_bit = false;
                if (expected_len == 1 + out.len) {
                    if ((reader.readByte() catch return error.InvalidEncoding) != 0) return error.InvalidEncoding;
                    expected_len -= 1;
                    has_top_bit = true;
                }
                const out_slice = out[out.len - expected_len ..];
                reader.readNoEof(out_slice) catch return error.InvalidEncoding;
                if (has_top_bit and out[0] >> 7 == 0) return error.InvalidEncoding;
            }

            /// Create a signature from a DER representation.
            /// Returns InvalidEncoding if the DER encoding is invalid.
            pub fn fromDer(der: []const u8) EncodingError!Signature {
                var sig: Signature = mem.zeroInit(Signature, .{});
                var fb = io.fixedBufferStream(der);
                const reader = fb.reader();
                var buf: [2]u8 = undefined;
                _ = reader.readNoEof(&buf) catch return error.InvalidEncoding;
                if (buf[0] != 0x30 or @as(usize, buf[1]) + 2 != der.len) {
                    return error.InvalidEncoding;
                }
                try readDerInt(&sig.r, reader);
                try readDerInt(&sig.s, reader);
                if (fb.getPos() catch unreachable != der.len) return error.InvalidEncoding;

                return sig;
            }
        };

        /// A Signer is used to incrementally compute a signature.
        /// It can be obtained from a `KeyPair`, using the `signer()` function.
        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,
            noise: ?[noise_length]u8,

            fn init(secret_key: SecretKey, noise: ?[noise_length]u8) !Signer {
                return Signer{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .noise = noise,
                };
            }

            /// Add new data to the message being signed.
            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            /// Compute a signature over the entire message.
            pub fn finalize(self: *Signer) (IdentityElementError || NonCanonicalError)!Signature {
                const scalar_encoded_length = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, scalar_encoded_length);
                var h: [h_len]u8 = [_]u8{0} ** h_len;
                const h_slice = h[h_len - Hash.digest_length .. h_len];
                self.h.final(h_slice);

                std.debug.assert(h.len >= scalar_encoded_length);
                const z = reduceToScalar(scalar_encoded_length, h[0..scalar_encoded_length].*);

                const k = deterministicScalar(h_slice.*, self.secret_key.bytes, self.noise);

                const p = try Curve.basePoint.mul(k.toBytes(.big), .big);
                const xs = p.affineCoordinates().x.toBytes(.big);
                const r = reduceToScalar(Curve.Fe.encoded_length, xs);
                if (r.isZero()) return error.IdentityElement;

                const k_inv = k.invert();
                const zrs = z.add(r.mul(try Curve.scalar.Scalar.fromBytes(self.secret_key.bytes, .big)));
                const s = k_inv.mul(zrs);
                if (s.isZero()) return error.IdentityElement;

                return Signature{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
            }
        };

        /// A Verifier is used to incrementally verify a signature.
        /// It can be obtained from a `Signature`, using the `verifier()` function.
        pub const Verifier = struct {
            h: Hash,
            r: Curve.scalar.Scalar,
            s: Curve.scalar.Scalar,
            public_key: PublicKey,

            fn init(sig: Signature, public_key: PublicKey) (IdentityElementError || NonCanonicalError)!Verifier {
                const r = try Curve.scalar.Scalar.fromBytes(sig.r, .big);
                const s = try Curve.scalar.Scalar.fromBytes(sig.s, .big);
                if (r.isZero() or s.isZero()) return error.IdentityElement;

                return Verifier{
                    .h = Hash.init(.{}),
                    .r = r,
                    .s = s,
                    .public_key = public_key,
                };
            }

            /// Add new content to the message to be verified.
            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }

            /// Verify that the signature is valid for the entire message.
            pub fn verify(self: *Verifier) (IdentityElementError || NonCanonicalError || SignatureVerificationError)!void {
                const ht = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, ht);
                var h: [h_len]u8 = [_]u8{0} ** h_len;
                self.h.final(h[h_len - Hash.digest_length .. h_len]);

                const z = reduceToScalar(ht, h[0..ht].*);
                if (z.isZero()) {
                    return error.SignatureVerificationFailed;
                }

                const s_inv = self.s.invert();
                const v1 = z.mul(s_inv).toBytes(.little);
                const v2 = self.r.mul(s_inv).toBytes(.little);
                const v1g = try Curve.basePoint.mulPublic(v1, .little);
                const v2pk = try self.public_key.p.mulPublic(v2, .little);
                const vxs = v1g.add(v2pk).affineCoordinates().x.toBytes(.big);
                const vr = reduceToScalar(Curve.Fe.encoded_length, vxs);
                if (!self.r.equivalent(vr)) {
                    return error.SignatureVerificationFailed;
                }
            }
        };

        /// An ECDSA key pair.
        pub const KeyPair = struct {
            /// Length (in bytes) of a seed required to create a key pair.
            pub const seed_length = noise_length;

            /// Public part.
            public_key: PublicKey,
            /// Secret scalar.
            secret_key: SecretKey,

            /// Create a new key pair. The seed must be secret and indistinguishable from random.
            /// The seed can also be left to null in order to generate a random key pair.
            pub fn create(seed: [seed_length]u8) IdentityElementError!KeyPair {
                const seed_ = seed;
                const h = [_]u8{0x00} ** Hash.digest_length;
                const k0 = [_]u8{0x01} ** SecretKey.encoded_length;
                const secret_key = deterministicScalar(h, k0, seed_).toBytes(.big);
                return fromSecretKey(SecretKey{ .bytes = secret_key });
            }

            /// Return the public key corresponding to the secret key.
            pub fn fromSecretKey(secret_key: SecretKey) IdentityElementError!KeyPair {
                const public_key = try Curve.basePoint.mul(secret_key.bytes, .big);
                return KeyPair{ .secret_key = secret_key, .public_key = PublicKey{ .p = public_key } };
            }

            /// Sign a message using the key pair.
            /// The noise can be null in order to create deterministic signatures.
            /// If deterministic signatures are not required, the noise should be randomly generated instead.
            /// This helps defend against fault attacks.
            pub fn sign(key_pair: KeyPair, msg: []const u8, noise: ?[noise_length]u8) (IdentityElementError || NonCanonicalError)!Signature {
                var st = try key_pair.signer(noise);
                st.update(msg);
                return st.finalize();
            }

            /// Create a Signer, that can be used for incremental signature verification.
            pub fn signer(key_pair: KeyPair, noise: ?[noise_length]u8) !Signer {
                return Signer.init(key_pair.secret_key, noise);
            }
        };

        // Reduce the coordinate of a field element to the scalar field.
        fn reduceToScalar(comptime unreduced_len: usize, s: [unreduced_len]u8) Curve.scalar.Scalar {
            if (unreduced_len >= 48) {
                var xs = [_]u8{0} ** 64;
                @memcpy(xs[xs.len - s.len ..], s[0..]);
                return Curve.scalar.Scalar.fromBytes64(xs, .big);
            }
            var xs = [_]u8{0} ** 48;
            @memcpy(xs[xs.len - s.len ..], s[0..]);
            return Curve.scalar.Scalar.fromBytes48(xs, .big);
        }

        // Create a deterministic scalar according to a secret key and optional noise.
        // This uses the overly conservative scheme from the "Deterministic ECDSA and EdDSA Signatures with Additional Randomness" draft.
        fn deterministicScalar(h: [Hash.digest_length]u8, secret_key: Curve.scalar.CompressedScalar, noise: ?[noise_length]u8) Curve.scalar.Scalar {
            var k = [_]u8{0x00} ** h.len;
            var m = [_]u8{0x00} ** (h.len + 1 + noise_length + secret_key.len + h.len);
            var t = [_]u8{0x00} ** Curve.scalar.encoded_length;
            const m_v = m[0..h.len];
            const m_i = &m[m_v.len];
            const m_z = m[m_v.len + 1 ..][0..noise_length];
            const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
            const m_h = m[m.len - h.len ..];

            @memset(m_v, 0x01);
            m_i.* = 0x00;
            if (noise) |n| @memcpy(m_z, &n);
            @memcpy(m_x, &secret_key);
            @memcpy(m_h, &h);
            Hmac.create(&k, &m, &k);
            Hmac.create(m_v, m_v, &k);
            m_i.* = 0x01;
            Hmac.create(&k, &m, &k);
            Hmac.create(m_v, m_v, &k);
            while (true) {
                var t_off: usize = 0;
                while (t_off < t.len) : (t_off += m_v.len) {
                    const t_end = @min(t_off + m_v.len, t.len);
                    Hmac.create(m_v, m_v, &k);
                    @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
                }
                if (Curve.scalar.Scalar.fromBytes(t, .big)) |s| return s else |_| {}
                m_i.* = 0x00;
                Hmac.create(&k, m[0 .. m_v.len + 1], &k);
                Hmac.create(m_v, m_v, &k);
            }
        }
    };
}
