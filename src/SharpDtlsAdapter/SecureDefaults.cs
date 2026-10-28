// SharpSRTP
// Copyright (C) 2025 Lukas Volf
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System;
using System.Collections.Generic;
using DtlsVersion = SharpDTLS.DtlsVersion;
using NamedGroups = SharpDTLS.NamedGroups;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// What the SharpDTLS peers allow by default: DTLS 1.2 and 1.3 only (RFC 8996 deprecates DTLS 1.0), forward-secret
    /// (EC)DHE key exchange and AEAD ciphers (RFC 9325 §4.2).
    /// </summary>
    internal static class SecureDefaults
    {
        /// <summary>
        /// The DTLS 1.3 suites, and the DTLS 1.2 ECDHE suites with AES-GCM or ChaCha20-Poly1305, in preference order. No CBC,
        /// RSA key transport, finite-field DHE, CCM_8 or PSK suites.
        /// </summary>
        public static IReadOnlyList<ushort> CipherSuites { get; } = new ushort[]
        {
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        };

        /// <summary>
        /// DTLS 1.3 key exchange groups: the X25519/ML-KEM-768 hybrid, X25519, P-256 and P-384; no finite-field groups.
        /// DTLS 1.2 ECDHE always uses X25519, P-256 or P-384.
        /// </summary>
        public static IReadOnlyList<ushort> SupportedGroups { get; } = new ushort[]
        {
            NamedGroups.X25519MlKem768, NamedGroups.X25519, NamedGroups.Secp256r1, NamedGroups.Secp384r1,
        };

        /// <summary>Throws unless <paramref name="version"/> is DTLS 1.2 or DTLS 1.3.</summary>
        public static ushort CheckVersion(ushort version)
        {
            if (version != DtlsVersion.Dtls12 && version != DtlsVersion.Dtls13)
            {
                throw new ArgumentOutOfRangeException(nameof(version), $"Only DTLS 1.2 and DTLS 1.3 are allowed, not 0x{version:X4}.");
            }
            return version;
        }
    }
}
