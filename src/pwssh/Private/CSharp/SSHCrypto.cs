// ==========================================================================
// PwSSH.Crypto — Pure managed SSH key operations
// No external dependencies beyond .NET Framework 4.7.2+ / .NET 6+
// ==========================================================================
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PwSSH.Crypto
{
    // ======================================================================
    // SSH Wire Format helpers
    // ======================================================================
    public static class SshWireFormat
    {
        public static void WriteUInt32(Stream s, uint v)
        {
            s.WriteByte((byte)(v >> 24));
            s.WriteByte((byte)(v >> 16));
            s.WriteByte((byte)(v >> 8));
            s.WriteByte((byte)v);
        }

        public static void WriteBytes(Stream s, byte[] data)
        {
            WriteUInt32(s, (uint)data.Length);
            s.Write(data, 0, data.Length);
        }

        public static void WriteString(Stream s, string str)
        {
            byte[] b = Encoding.ASCII.GetBytes(str);
            WriteBytes(s, b);
        }

        public static void WriteMPInt(Stream s, BigInteger v)
        {
            if (v.IsZero)
            {
                WriteUInt32(s, 0);
                return;
            }
            byte[] raw = v.ToByteArray(); // little-endian, two's complement
            Array.Reverse(raw); // now big-endian
            // Strip leading zero bytes (but keep one if needed for sign)
            int start = 0;
            while (start < raw.Length - 1 && raw[start] == 0) start++;
            int len = raw.Length - start;
            WriteUInt32(s, (uint)len);
            s.Write(raw, start, len);
        }

        public static uint ReadUInt32(Stream s)
        {
            byte[] buf = new byte[4];
            int read = s.Read(buf, 0, 4);
            if (read < 4) throw new InvalidDataException("Unexpected end of data");
            return ((uint)buf[0] << 24) | ((uint)buf[1] << 16) | ((uint)buf[2] << 8) | buf[3];
        }

        public static byte[] ReadBytes(Stream s)
        {
            uint len = ReadUInt32(s);
            if (len > 1048576) throw new InvalidDataException("Data too large");
            byte[] buf = new byte[len];
            int read = s.Read(buf, 0, (int)len);
            if (read < (int)len) throw new InvalidDataException("Unexpected end of data");
            return buf;
        }

        public static string ReadString(Stream s)
        {
            return Encoding.ASCII.GetString(ReadBytes(s));
        }

        public static BigInteger ReadMPInt(Stream s)
        {
            byte[] raw = ReadBytes(s);
            if (raw.Length == 0) return BigInteger.Zero;
            // raw is big-endian, convert to little-endian for BigInteger
            byte[] le = new byte[raw.Length + 1]; // extra byte for positive sign
            for (int i = 0; i < raw.Length; i++)
                le[raw.Length - 1 - i] = raw[i];
            return new BigInteger(le);
        }
    }

    // ======================================================================
    // Ed25519 — BigInteger-based implementation (RFC 8032)
    // ======================================================================
    public static class Ed25519
    {
        // Curve parameters
        private static readonly BigInteger P = (BigInteger.One << 255) - 19;
        private static readonly BigInteger D;
        private static readonly BigInteger I; // sqrt(-1) mod p
        private static readonly BigInteger By;
        private static readonly BigInteger Bx;

        // Group order
        private static readonly BigInteger L =
            (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

        static Ed25519()
        {
            D = Mod(-121665 * ModInverse(121666, P), P);
            I = BigInteger.ModPow(2, (P - 1) / 4, P); // sqrt(-1)
            By = Mod(4 * ModInverse(5, P), P);
            Bx = RecoverX(By);
            // Base point sign bit should be 0 (even x)
            if (!Bx.IsEven) Bx = P - Bx;
        }

        /// <summary>
        /// Generate an Ed25519 public key from a 32-byte seed.
        /// Returns (publicKey[32], expandedPrivate[64]) where
        /// expandedPrivate = seed || publicKey.
        /// </summary>
        public static void GenerateKeyPair(byte[] seed, out byte[] publicKey, out byte[] expandedPrivate)
        {
            if (seed == null || seed.Length != 32)
                throw new ArgumentException("Seed must be exactly 32 bytes.");

            byte[] h;
            using (var sha = SHA512.Create()) { h = sha.ComputeHash(seed); }

            // Clamp
            h[0] &= 248;
            h[31] &= 127;
            h[31] |= 64;

            byte[] scalarBytes = new byte[32];
            Array.Copy(h, 0, scalarBytes, 0, 32);
            BigInteger a = FromLE(scalarBytes);

            // A = a * B
            BigInteger ax, ay;
            ScalarMult(Bx, By, a, out ax, out ay);

            publicKey = EncodePoint(ax, ay);
            expandedPrivate = new byte[64];
            Array.Copy(seed, 0, expandedPrivate, 0, 32);
            Array.Copy(publicKey, 0, expandedPrivate, 32, 32);
        }

        // --- Field arithmetic ---

        private static BigInteger Mod(BigInteger a, BigInteger p)
        {
            BigInteger r = BigInteger.Remainder(a, p);
            return r.Sign < 0 ? r + p : r;
        }

        private static BigInteger ModInverse(BigInteger a, BigInteger p)
        {
            return BigInteger.ModPow(Mod(a, p), p - 2, p);
        }

        private static BigInteger RecoverX(BigInteger y)
        {
            // x^2 = (y^2 - 1) * inv(d*y^2 + 1) mod p
            BigInteger y2 = Mod(y * y, P);
            BigInteger x2 = Mod((y2 - 1) * ModInverse(Mod(D * y2 + 1, P), P), P);

            // Tonelli-Shanks for p = 5 (mod 8)
            BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
            if (Mod(x * x - x2, P) != BigInteger.Zero)
            {
                x = Mod(x * I, P);
            }
            if (Mod(x * x - x2, P) != BigInteger.Zero)
            {
                throw new ArithmeticException("No square root exists for this y coordinate.");
            }
            return x;
        }

        // --- Extended coordinates: (X, Y, Z, T) where x=X/Z, y=Y/Z, T=XY/Z ---

        private static void PointAdd(
            BigInteger x1, BigInteger y1, BigInteger z1, BigInteger t1,
            BigInteger x2, BigInteger y2, BigInteger z2, BigInteger t2,
            out BigInteger x3, out BigInteger y3, out BigInteger z3, out BigInteger t3)
        {
            BigInteger a = Mod(x1 * x2, P);
            BigInteger b = Mod(y1 * y2, P);
            BigInteger c = Mod(t1 * D * t2, P);
            BigInteger d2 = Mod(z1 * z2, P);
            BigInteger e = Mod((x1 + y1) * (x2 + y2) - a - b, P);
            BigInteger f = Mod(d2 - c, P);
            BigInteger g = Mod(d2 + c, P);
            BigInteger h = Mod(b + a, P); // a_coeff = -1, so h = b - (-1)*a = b + a

            x3 = Mod(e * f, P);
            y3 = Mod(g * h, P);
            t3 = Mod(e * h, P);
            z3 = Mod(f * g, P);
        }

        private static void PointDouble(
            BigInteger x1, BigInteger y1, BigInteger z1, BigInteger t1,
            out BigInteger x3, out BigInteger y3, out BigInteger z3, out BigInteger t3)
        {
            BigInteger a = Mod(x1 * x1, P);
            BigInteger b = Mod(y1 * y1, P);
            BigInteger c = Mod(2 * z1 * z1, P);
            BigInteger dd = Mod(P - a, P); // d = -a (since curve a_coeff = -1)
            BigInteger e = Mod((x1 + y1) * (x1 + y1) - a - b, P);
            BigInteger g = Mod(dd + b, P);
            BigInteger f = Mod(g - c, P);
            BigInteger h = Mod(dd - b, P);

            x3 = Mod(e * f, P);
            y3 = Mod(g * h, P);
            t3 = Mod(e * h, P);
            z3 = Mod(f * g, P);
        }

        private static void ScalarMult(BigInteger bx, BigInteger by, BigInteger scalar,
            out BigInteger rx, out BigInteger ry)
        {
            // Identity in extended coords: (0, 1, 1, 0)
            BigInteger x = BigInteger.Zero, y = BigInteger.One, z = BigInteger.One, t = BigInteger.Zero;
            BigInteger qx = bx, qy = by, qz = BigInteger.One, qt = Mod(bx * by, P);

            // Double-and-add (constant-ish time not needed for keygen)
            int bits = (int)scalar.GetBitLength();
            for (int i = bits - 1; i >= 0; i--)
            {
                BigInteger nx, ny, nz, nt;
                PointDouble(x, y, z, t, out nx, out ny, out nz, out nt);
                x = nx; y = ny; z = nz; t = nt;

                if ((scalar >> i & 1) == 1)
                {
                    PointAdd(x, y, z, t, qx, qy, qz, qt, out nx, out ny, out nz, out nt);
                    x = nx; y = ny; z = nz; t = nt;
                }
            }

            // Affine conversion
            BigInteger zinv = ModInverse(z, P);
            rx = Mod(x * zinv, P);
            ry = Mod(y * zinv, P);
        }

        /// <summary>Encode a point as 32 bytes (RFC 8032 encoding).</summary>
        public static byte[] EncodePoint(BigInteger x, BigInteger y)
        {
            byte[] enc = ToLE(y, 32);
            if (!x.IsEven) enc[31] |= 0x80; // store sign of x in high bit
            return enc;
        }

        /// <summary>Decode 32 bytes to a curve point.</summary>
        public static void DecodePoint(byte[] encoded, out BigInteger x, out BigInteger y)
        {
            if (encoded.Length != 32)
                throw new ArgumentException("Encoded point must be 32 bytes.");

            byte[] ybytes = (byte[])encoded.Clone();
            bool xSign = (ybytes[31] & 0x80) != 0;
            ybytes[31] &= 0x7F;
            y = FromLE(ybytes);

            x = RecoverX(y);
            bool xIsOdd = !x.IsEven;
            if (xSign != xIsOdd) x = P - x;
        }

        // --- Byte array helpers ---

        private static BigInteger FromLE(byte[] b)
        {
            byte[] padded = new byte[b.Length + 1]; // ensure positive
            Array.Copy(b, 0, padded, 0, b.Length);
            return new BigInteger(padded);
        }

        private static byte[] ToLE(BigInteger v, int size)
        {
            byte[] raw = v.ToByteArray();
            byte[] result = new byte[size];
            int len = Math.Min(raw.Length, size);
            Array.Copy(raw, 0, result, 0, len);
            return result;
        }
    }

    // ======================================================================
    // Blowfish cipher (for bcrypt_pbkdf)
    // ======================================================================
    internal class BlowfishCipher
    {
        private uint[] _p;
        private uint[] _s; // 4 * 256

        private static readonly uint[] P0 = new uint[]
        {
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
            0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
            0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            0x9216d5d9, 0x8979fb1b
        };

        private static readonly uint[] S0 = new uint[]
        {
            // S-box 0
            0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
            0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
            0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
            0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
            0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
            0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
            0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
            0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
            0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
            0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
            0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
            0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
            0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
            0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
            0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
            0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
            0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
            0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
            0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
            0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
            0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
            0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
            0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
            0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
            0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
            0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
            0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
            0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
            0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
            0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
            0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
            0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
            0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
            0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
            0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
            0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
            0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
            0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
            0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
            0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
            0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
            0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
            0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
            0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
            0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
            0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
            0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
            0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
            0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
            0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
            0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
            0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
            0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
            0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
            0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
            0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
            0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
            0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
            0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
            0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
            0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
            0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
            0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
            0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
            // S-box 1
            0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
            0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
            0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
            0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
            0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
            0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
            0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
            0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
            0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
            0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
            0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
            0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
            0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
            0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
            0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
            0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
            0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
            0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
            0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
            0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
            0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
            0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
            0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
            0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
            0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
            0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
            0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
            0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
            0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
            0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
            0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
            0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
            0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
            0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
            0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
            0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
            0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
            0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
            0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
            0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
            0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
            0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
            0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
            0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
            0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
            0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
            0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
            0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
            0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
            0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
            0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
            0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
            0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
            0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
            0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
            0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
            0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
            0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
            0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
            0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
            0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
            0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
            0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
            0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
            // S-box 2
            0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
            0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
            0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
            0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
            0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
            0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
            0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
            0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
            0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
            0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
            0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
            0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
            0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
            0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
            0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
            0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
            0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
            0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
            0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
            0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
            0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
            0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
            0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
            0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
            0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
            0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
            0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
            0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
            0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
            0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
            0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
            0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
            0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
            0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
            0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
            0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
            0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
            0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
            0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
            0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
            0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
            0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
            0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
            0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
            0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
            0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
            0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
            0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
            0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
            0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
            0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
            0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
            0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
            0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
            0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
            0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
            0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
            0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
            0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
            0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
            0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
            0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
            0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
            0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
            // S-box 3
            0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
            0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
            0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
            0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
            0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
            0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
            0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
            0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
            0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
            0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
            0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
            0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
            0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
            0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
            0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
            0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
            0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
            0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
            0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
            0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
            0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
            0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
            0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
            0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
            0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
            0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
            0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
            0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
            0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
            0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
            0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
            0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
            0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
            0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
            0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
            0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
            0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
            0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
            0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
            0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
            0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
            0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
            0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
            0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
            0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
            0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
            0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
            0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
            0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
            0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
            0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
            0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
            0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
            0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
            0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
            0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
            0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
            0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
            0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
            0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
            0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
            0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
            0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
            0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
        };

        public BlowfishCipher()
        {
            _p = (uint[])P0.Clone();
            _s = (uint[])S0.Clone();
        }

        public void Encipher(ref uint xl, ref uint xr)
        {
            for (int i = 0; i < 16; i += 2)
            {
                xl ^= _p[i];
                xr ^= F(xl);
                xr ^= _p[i + 1];
                xl ^= F(xr);
            }
            xr ^= _p[16];
            xl ^= _p[17];
            uint tmp = xl; xl = xr; xr = tmp;
        }

        public void Decipher(ref uint xl, ref uint xr)
        {
            for (int i = 16; i > 0; i -= 2)
            {
                xl ^= _p[i + 1];
                xr ^= F(xl);
                xr ^= _p[i];
                xl ^= F(xr);
            }
            xr ^= _p[1];
            xl ^= _p[0];
            uint tmp = xl; xl = xr; xr = tmp;
        }

        private uint F(uint x)
        {
            uint a = _s[(x >> 24) & 0xFF];
            uint b = _s[256 + ((x >> 16) & 0xFF)];
            uint c = _s[512 + ((x >> 8) & 0xFF)];
            uint d = _s[768 + (x & 0xFF)];
            return ((a + b) ^ c) + d;
        }

        /// <summary>Initialize state then expand with salt and key (for bcrypt).</summary>
        public void ExpandState(byte[] salt, byte[] key)
        {
            int koff = 0;
            for (int i = 0; i < 18; i++)
            {
                _p[i] ^= StreamToUInt32(key, ref koff);
            }

            int soff = 0;
            uint l = 0, r = 0;
            for (int i = 0; i < 18; i += 2)
            {
                l ^= StreamToUInt32(salt, ref soff);
                r ^= StreamToUInt32(salt, ref soff);
                Encipher(ref l, ref r);
                _p[i] = l;
                _p[i + 1] = r;
            }
            for (int i = 0; i < 1024; i += 2)
            {
                l ^= StreamToUInt32(salt, ref soff);
                r ^= StreamToUInt32(salt, ref soff);
                Encipher(ref l, ref r);
                _s[i] = l;
                _s[i + 1] = r;
            }
        }

        /// <summary>Expand state with data only (key=0 variant for bcrypt rounds).</summary>
        public void Expand0State(byte[] data)
        {
            int off = 0;
            for (int i = 0; i < 18; i++)
            {
                _p[i] ^= StreamToUInt32(data, ref off);
            }

            uint l = 0, r = 0;
            for (int i = 0; i < 18; i += 2)
            {
                Encipher(ref l, ref r);
                _p[i] = l;
                _p[i + 1] = r;
            }
            for (int i = 0; i < 1024; i += 2)
            {
                Encipher(ref l, ref r);
                _s[i] = l;
                _s[i + 1] = r;
            }
        }

        private static uint StreamToUInt32(byte[] data, ref int off)
        {
            uint result = 0;
            for (int i = 0; i < 4; i++)
            {
                result = (result << 8) | data[off];
                off = (off + 1) % data.Length;
            }
            return result;
        }
    }

    // ======================================================================
    // bcrypt_pbkdf (OpenSSH variant)
    // ======================================================================
    public static class BcryptPbkdf
    {
        // "OxychromaticBlowfishSwatDynamite"
        private static readonly byte[] BcryptCtext = Encoding.ASCII.GetBytes("OxychromaticBlowfishSwatDynamite");

        /// <summary>
        /// Derive key material using OpenSSH bcrypt_pbkdf.
        /// </summary>
        public static byte[] DeriveKey(byte[] password, byte[] salt, int rounds, int keyLength)
        {
            if (rounds < 1) throw new ArgumentException("Rounds must be >= 1");

            byte[] sha2pass;
            using (var sha = SHA512.Create()) { sha2pass = sha.ComputeHash(password); }

            int numBlocks = (keyLength + 31) / 32;
            byte[] output = new byte[numBlocks * 32];

            for (int block = 1; block <= numBlocks; block++)
            {
                // SHA-512(salt || block_number_BE)
                byte[] sha2salt;
                using (var sha = SHA512.Create())
                {
                    sha.TransformBlock(salt, 0, salt.Length, null, 0);
                    byte[] ctr = new byte[4];
                    ctr[0] = (byte)(block >> 24);
                    ctr[1] = (byte)(block >> 16);
                    ctr[2] = (byte)(block >> 8);
                    ctr[3] = (byte)block;
                    sha.TransformFinalBlock(ctr, 0, 4);
                    sha2salt = sha.Hash;
                }

                byte[] outBlock = BcryptHash(sha2pass, sha2salt);
                byte[] tmpOut = (byte[])outBlock.Clone();

                for (int r = 1; r < rounds; r++)
                {
                    // SHA-512 the previous output to get new salt
                    using (var sha = SHA512.Create()) { sha2salt = sha.ComputeHash(outBlock); }
                    outBlock = BcryptHash(sha2pass, sha2salt);
                    for (int j = 0; j < 32; j++) tmpOut[j] ^= outBlock[j];
                }

                Array.Copy(tmpOut, 0, output, (block - 1) * 32, 32);
            }

            // Interleave bytes per OpenSSH convention
            byte[] result = new byte[keyLength];
            int stride = numBlocks * 32;
            for (int i = 0; i < keyLength; i++)
            {
                int srcBlock = i / 32;
                int srcByte = i % 32;
                int srcIdx = srcByte * numBlocks + srcBlock;
                if (srcIdx < output.Length)
                    result[i] = output[srcIdx];
            }
            return result;
        }

        private static byte[] BcryptHash(byte[] sha2pass, byte[] sha2salt)
        {
            var bf = new BlowfishCipher();
            bf.ExpandState(sha2salt, sha2pass);
            for (int i = 0; i < 64; i++)
            {
                bf.Expand0State(sha2salt);
                bf.Expand0State(sha2pass);
            }

            // Encrypt "OxychromaticBlowfishSwatDynamite" (8 x uint32)
            uint[] cdata = new uint[8];
            for (int i = 0; i < 8; i++)
            {
                cdata[i] = ((uint)BcryptCtext[i * 4] << 24) |
                           ((uint)BcryptCtext[i * 4 + 1] << 16) |
                           ((uint)BcryptCtext[i * 4 + 2] << 8) |
                           BcryptCtext[i * 4 + 3];
            }
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < 8; j += 2)
                {
                    bf.Encipher(ref cdata[j], ref cdata[j + 1]);
                }
            }

            // Output 32 bytes (big-endian)
            byte[] result = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                result[i * 4] = (byte)(cdata[i] >> 24);
                result[i * 4 + 1] = (byte)(cdata[i] >> 16);
                result[i * 4 + 2] = (byte)(cdata[i] >> 8);
                result[i * 4 + 3] = (byte)cdata[i];
            }
            return result;
        }
    }

    // ======================================================================
    // AES-CTR mode (used for key file encryption)
    // ======================================================================
    public static class AesCtr
    {
        public static byte[] Transform(byte[] key, byte[] iv, byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;

                byte[] counter = (byte[])iv.Clone();
                byte[] result = new byte[data.Length];
                byte[] block = new byte[16];

                using (var enc = aes.CreateEncryptor())
                {
                    for (int offset = 0; offset < data.Length; offset += 16)
                    {
                        enc.TransformBlock(counter, 0, 16, block, 0);
                        int len = Math.Min(16, data.Length - offset);
                        for (int i = 0; i < len; i++)
                            result[offset + i] = (byte)(data[offset + i] ^ block[i]);
                        IncrementCounter(counter);
                    }
                }
                return result;
            }
        }

        private static void IncrementCounter(byte[] ctr)
        {
            for (int i = ctr.Length - 1; i >= 0; i--)
            {
                if (++ctr[i] != 0) break;
            }
        }
    }

    // ======================================================================
    // OpenSSH key format reader/writer
    // ======================================================================
    public static class OpenSshKeyFormat
    {
        private const string AUTH_MAGIC = "openssh-key-v1";
        private const string CIPHER_NONE = "none";
        private const string CIPHER_AES256CTR = "aes256-ctr";
        private const string KDF_NONE = "none";
        private const string KDF_BCRYPT = "bcrypt";

        // ---- Key data container ----

        public class SshKeyData
        {
            public string KeyType;
            public byte[] PublicKeyBlob;
            public string Comment;
            // For Ed25519
            public byte[] Ed25519Seed;
            public byte[] Ed25519PublicKey;
            // For RSA
            public RSAParameters RsaParameters;
            // For ECDSA
            public string EcCurveName;
            public byte[] EcPublicPoint;
            public byte[] EcPrivateKey;
        }

        // ---- Generation ----

        public static SshKeyData GenerateEd25519(string comment)
        {
            byte[] seed = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(seed); }

            byte[] pubKey, expandedPriv;
            Ed25519.GenerateKeyPair(seed, out pubKey, out expandedPriv);

            var data = new SshKeyData();
            data.KeyType = "ssh-ed25519";
            data.Comment = comment;
            data.Ed25519Seed = seed;
            data.Ed25519PublicKey = pubKey;

            using (var ms = new MemoryStream())
            {
                SshWireFormat.WriteString(ms, "ssh-ed25519");
                SshWireFormat.WriteBytes(ms, pubKey);
                data.PublicKeyBlob = ms.ToArray();
            }

            return data;
        }

        public static SshKeyData GenerateRsa(int bits, string comment)
        {
            using (var rsa = RSA.Create(bits))
            {
                var p = rsa.ExportParameters(true);
                var data = new SshKeyData();
                data.KeyType = "ssh-rsa";
                data.Comment = comment;
                data.RsaParameters = p;

                using (var ms = new MemoryStream())
                {
                    SshWireFormat.WriteString(ms, "ssh-rsa");
                    SshWireFormat.WriteMPInt(ms, new BigInteger(ReverseAndPad(p.Exponent)));
                    SshWireFormat.WriteMPInt(ms, new BigInteger(ReverseAndPad(p.Modulus)));
                    data.PublicKeyBlob = ms.ToArray();
                }

                return data;
            }
        }

        public static SshKeyData GenerateEcdsa(int bits, string comment)
        {
            string curveName;
            string keyTypeName;
            ECCurve curve;
            switch (bits)
            {
                case 384:
                    curveName = "nistp384";
                    keyTypeName = "ecdsa-sha2-nistp384";
                    curve = ECCurve.NamedCurves.nistP384;
                    break;
                case 521:
                    curveName = "nistp521";
                    keyTypeName = "ecdsa-sha2-nistp521";
                    curve = ECCurve.NamedCurves.nistP521;
                    break;
                default: // 256
                    curveName = "nistp256";
                    keyTypeName = "ecdsa-sha2-nistp256";
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
            }

            using (var ecdsa = ECDsa.Create(curve))
            {
                var p = ecdsa.ExportParameters(true);
                var data = new SshKeyData();
                data.KeyType = keyTypeName;
                data.Comment = comment;
                data.EcCurveName = curveName;
                data.EcPrivateKey = p.D;

                // Build uncompressed public point: 0x04 || X || Y
                byte[] point = new byte[1 + p.Q.X.Length + p.Q.Y.Length];
                point[0] = 0x04;
                Array.Copy(p.Q.X, 0, point, 1, p.Q.X.Length);
                Array.Copy(p.Q.Y, 0, point, 1 + p.Q.X.Length, p.Q.Y.Length);
                data.EcPublicPoint = point;

                using (var ms = new MemoryStream())
                {
                    SshWireFormat.WriteString(ms, keyTypeName);
                    SshWireFormat.WriteString(ms, curveName);
                    SshWireFormat.WriteBytes(ms, point);
                    data.PublicKeyBlob = ms.ToArray();
                }

                return data;
            }
        }

        // ---- Formatting ----

        public static string FormatPublicKeyLine(SshKeyData key)
        {
            string b64 = Convert.ToBase64String(key.PublicKeyBlob);
            return String.Format("{0} {1} {2}", key.KeyType, b64, key.Comment);
        }

        public static string FormatPrivateKeyFile(SshKeyData key, string passphrase)
        {
            bool encrypt = !String.IsNullOrEmpty(passphrase);
            string cipherName = encrypt ? CIPHER_AES256CTR : CIPHER_NONE;
            string kdfName = encrypt ? KDF_BCRYPT : KDF_NONE;

            byte[] salt = null;
            int rounds = 16;
            byte[] kdfOptions;

            if (encrypt)
            {
                salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(salt); }

                using (var ms = new MemoryStream())
                {
                    SshWireFormat.WriteBytes(ms, salt);
                    SshWireFormat.WriteUInt32(ms, (uint)rounds);
                    kdfOptions = ms.ToArray();
                }
            }
            else
            {
                kdfOptions = new byte[0];
            }

            // Build private section (unencrypted)
            byte[] privSection;
            using (var ms = new MemoryStream())
            {
                byte[] checkBytes = new byte[4];
                using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(checkBytes); }
                uint check = ((uint)checkBytes[0] << 24) | ((uint)checkBytes[1] << 16) |
                             ((uint)checkBytes[2] << 8) | checkBytes[3];

                SshWireFormat.WriteUInt32(ms, check);
                SshWireFormat.WriteUInt32(ms, check);

                WritePrivateKeyData(ms, key);
                SshWireFormat.WriteString(ms, key.Comment);

                // Padding: 1, 2, 3, 4, 5, 6, 7, ...
                int blockSize = encrypt ? 16 : 8;
                int padLen = blockSize - ((int)ms.Length % blockSize);
                if (padLen == blockSize) padLen = 0;
                for (int i = 0; i < padLen; i++)
                    ms.WriteByte((byte)((i + 1) & 0xFF));

                privSection = ms.ToArray();
            }

            // Encrypt if needed
            if (encrypt)
            {
                byte[] passBytes = Encoding.UTF8.GetBytes(passphrase);
                byte[] derived = BcryptPbkdf.DeriveKey(passBytes, salt, rounds, 48); // 32 key + 16 iv
                byte[] aesKey = new byte[32];
                byte[] aesIv = new byte[16];
                Array.Copy(derived, 0, aesKey, 0, 32);
                Array.Copy(derived, 32, aesIv, 0, 16);
                privSection = AesCtr.Transform(aesKey, aesIv, privSection);
            }

            // Build full file
            byte[] fileBytes;
            using (var ms = new MemoryStream())
            {
                byte[] magic = Encoding.ASCII.GetBytes(AUTH_MAGIC);
                ms.Write(magic, 0, magic.Length);
                ms.WriteByte(0); // null terminator

                SshWireFormat.WriteString(ms, cipherName);
                SshWireFormat.WriteString(ms, kdfName);
                SshWireFormat.WriteBytes(ms, kdfOptions);
                SshWireFormat.WriteUInt32(ms, 1); // number of keys
                SshWireFormat.WriteBytes(ms, key.PublicKeyBlob);
                SshWireFormat.WriteBytes(ms, privSection);

                fileBytes = ms.ToArray();
            }

            // PEM wrap
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");
            string b64 = Convert.ToBase64String(fileBytes);
            for (int i = 0; i < b64.Length; i += 70)
            {
                int len = Math.Min(70, b64.Length - i);
                sb.AppendLine(b64.Substring(i, len));
            }
            sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
            return sb.ToString();
        }

        private static void WritePrivateKeyData(Stream s, SshKeyData key)
        {
            if (key.KeyType == "ssh-ed25519")
            {
                SshWireFormat.WriteString(s, "ssh-ed25519");
                SshWireFormat.WriteBytes(s, key.Ed25519PublicKey);
                // 64 bytes: seed (32) + pubkey (32)
                byte[] combined = new byte[64];
                Array.Copy(key.Ed25519Seed, 0, combined, 0, 32);
                Array.Copy(key.Ed25519PublicKey, 0, combined, 32, 32);
                SshWireFormat.WriteBytes(s, combined);
            }
            else if (key.KeyType == "ssh-rsa")
            {
                var p = key.RsaParameters;
                SshWireFormat.WriteString(s, "ssh-rsa");
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.Modulus)));
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.Exponent)));
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.D)));
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.InverseQ)));
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.P)));
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(p.Q)));
            }
            else if (key.KeyType.StartsWith("ecdsa-sha2-"))
            {
                SshWireFormat.WriteString(s, key.KeyType);
                SshWireFormat.WriteString(s, key.EcCurveName);
                SshWireFormat.WriteBytes(s, key.EcPublicPoint);
                SshWireFormat.WriteMPInt(s, new BigInteger(ReverseAndPad(key.EcPrivateKey)));
            }
        }

        // ---- Parsing ----

        public static SshKeyData ParsePrivateKeyFile(string pemText, string passphrase)
        {
            // Strip PEM headers
            string b64 = pemText
                .Replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                .Replace("-----END OPENSSH PRIVATE KEY-----", "")
                .Replace("\r", "").Replace("\n", "").Trim();

            byte[] raw = Convert.FromBase64String(b64);

            using (var ms = new MemoryStream(raw))
            {
                // Verify magic
                byte[] magicBuf = new byte[AUTH_MAGIC.Length + 1];
                ms.Read(magicBuf, 0, magicBuf.Length);
                string magic = Encoding.ASCII.GetString(magicBuf, 0, AUTH_MAGIC.Length);
                if (magic != AUTH_MAGIC || magicBuf[AUTH_MAGIC.Length] != 0)
                    throw new InvalidDataException("Not an OpenSSH private key file.");

                string cipherName = SshWireFormat.ReadString(ms);
                string kdfName = SshWireFormat.ReadString(ms);
                byte[] kdfOptions = SshWireFormat.ReadBytes(ms);
                uint numKeys = SshWireFormat.ReadUInt32(ms);
                byte[] pubBlob = SshWireFormat.ReadBytes(ms);
                byte[] privSection = SshWireFormat.ReadBytes(ms);

                // Decrypt if needed
                if (cipherName != CIPHER_NONE)
                {
                    if (String.IsNullOrEmpty(passphrase))
                        throw new CryptographicException("Key is encrypted but no passphrase provided.");

                    if (cipherName != CIPHER_AES256CTR)
                        throw new NotSupportedException("Unsupported cipher: " + cipherName);

                    using (var kdfStream = new MemoryStream(kdfOptions))
                    {
                        byte[] salt = SshWireFormat.ReadBytes(kdfStream);
                        uint rounds = SshWireFormat.ReadUInt32(kdfStream);

                        byte[] passBytes = Encoding.UTF8.GetBytes(passphrase);
                        byte[] derived = BcryptPbkdf.DeriveKey(passBytes, salt, (int)rounds, 48);
                        byte[] aesKey = new byte[32];
                        byte[] aesIv = new byte[16];
                        Array.Copy(derived, 0, aesKey, 0, 32);
                        Array.Copy(derived, 32, aesIv, 0, 16);
                        privSection = AesCtr.Transform(aesKey, aesIv, privSection);
                    }
                }

                // Parse private section
                using (var ps = new MemoryStream(privSection))
                {
                    uint check1 = SshWireFormat.ReadUInt32(ps);
                    uint check2 = SshWireFormat.ReadUInt32(ps);
                    if (check1 != check2)
                        throw new CryptographicException("Incorrect passphrase or corrupted key.");

                    string keyType = SshWireFormat.ReadString(ps);
                    var data = new SshKeyData();
                    data.KeyType = keyType;
                    data.PublicKeyBlob = pubBlob;

                    if (keyType == "ssh-ed25519")
                    {
                        data.Ed25519PublicKey = SshWireFormat.ReadBytes(ps);
                        byte[] combined = SshWireFormat.ReadBytes(ps); // 64 bytes
                        data.Ed25519Seed = new byte[32];
                        Array.Copy(combined, 0, data.Ed25519Seed, 0, 32);
                    }
                    else if (keyType == "ssh-rsa")
                    {
                        BigInteger n = SshWireFormat.ReadMPInt(ps);
                        BigInteger e = SshWireFormat.ReadMPInt(ps);
                        BigInteger d = SshWireFormat.ReadMPInt(ps);
                        BigInteger iqmp = SshWireFormat.ReadMPInt(ps);
                        BigInteger p = SshWireFormat.ReadMPInt(ps);
                        BigInteger q = SshWireFormat.ReadMPInt(ps);

                        var rp = new RSAParameters();
                        rp.Modulus = ToBigEndianBytes(n);
                        rp.Exponent = ToBigEndianBytes(e);
                        rp.D = ToBigEndianBytes(d);
                        rp.InverseQ = ToBigEndianBytes(iqmp);
                        rp.P = ToBigEndianBytes(p);
                        rp.Q = ToBigEndianBytes(q);
                        // Compute DP and DQ
                        rp.DP = ToBigEndianBytes(BigInteger.Remainder(d, p - 1));
                        rp.DQ = ToBigEndianBytes(BigInteger.Remainder(d, q - 1));
                        data.RsaParameters = rp;
                    }
                    else if (keyType.StartsWith("ecdsa-sha2-"))
                    {
                        data.EcCurveName = SshWireFormat.ReadString(ps);
                        data.EcPublicPoint = SshWireFormat.ReadBytes(ps);
                        BigInteger privScalar = SshWireFormat.ReadMPInt(ps);
                        data.EcPrivateKey = ToBigEndianBytes(privScalar);
                    }

                    data.Comment = SshWireFormat.ReadString(ps);
                    return data;
                }
            }
        }

        public static SshKeyData ParsePublicKeyLine(string line)
        {
            string[] parts = line.Trim().Split(new char[] { ' ', '\t' }, 3,
                StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                throw new FormatException("Invalid public key line.");

            var data = new SshKeyData();
            data.KeyType = parts[0];
            data.PublicKeyBlob = Convert.FromBase64String(parts[1]);
            data.Comment = parts.Length > 2 ? parts[2] : "";

            // Parse the blob to extract key-type-specific fields
            using (var ms = new MemoryStream(data.PublicKeyBlob))
            {
                string blobType = SshWireFormat.ReadString(ms);
                if (blobType == "ssh-ed25519")
                {
                    data.Ed25519PublicKey = SshWireFormat.ReadBytes(ms);
                }
                else if (blobType == "ssh-rsa")
                {
                    BigInteger e = SshWireFormat.ReadMPInt(ms);
                    BigInteger n = SshWireFormat.ReadMPInt(ms);
                    var rp = new RSAParameters();
                    rp.Exponent = ToBigEndianBytes(e);
                    rp.Modulus = ToBigEndianBytes(n);
                    data.RsaParameters = rp;
                }
                else if (blobType.StartsWith("ecdsa-sha2-"))
                {
                    data.EcCurveName = SshWireFormat.ReadString(ms);
                    data.EcPublicPoint = SshWireFormat.ReadBytes(ms);
                }
            }

            return data;
        }

        // ---- Fingerprint ----

        public static string Fingerprint(byte[] publicKeyBlob, string algorithm)
        {
            if (algorithm == "SHA256")
            {
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(publicKeyBlob);
                    return "SHA256:" + Convert.ToBase64String(hash).TrimEnd('=');
                }
            }
            else // MD5
            {
                using (var md5 = MD5.Create())
                {
                    byte[] hash = md5.ComputeHash(publicKeyBlob);
                    var sb = new StringBuilder();
                    for (int i = 0; i < hash.Length; i++)
                    {
                        if (i > 0) sb.Append(':');
                        sb.Append(hash[i].ToString("x2"));
                    }
                    return "MD5:" + sb.ToString();
                }
            }
        }

        // ---- Helpers ----

        /// <summary>Reverse byte array and pad with 0x00 for positive BigInteger.</summary>
        private static byte[] ReverseAndPad(byte[] bigEndian)
        {
            byte[] le = new byte[bigEndian.Length + 1];
            for (int i = 0; i < bigEndian.Length; i++)
                le[bigEndian.Length - 1 - i] = bigEndian[i];
            return le;
        }

        /// <summary>Convert BigInteger to big-endian byte array (no sign byte).</summary>
        private static byte[] ToBigEndianBytes(BigInteger v)
        {
            byte[] le = v.ToByteArray(); // little-endian with possible sign byte
            // Trim trailing zero (sign byte)
            int len = le.Length;
            while (len > 1 && le[len - 1] == 0) len--;
            byte[] be = new byte[len];
            for (int i = 0; i < len; i++)
                be[len - 1 - i] = le[i];
            return be;
        }
    }
}
