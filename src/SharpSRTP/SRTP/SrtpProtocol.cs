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

using System.Collections.Generic;

namespace SharpSRTP.SRTP
{
    /// <summary>
    /// Currently registered SRTP Crypto Suites https://www.iana.org/assignments/sdp-security-descriptions/sdp-security-descriptions.xhtml
    /// </summary>
    public abstract class SrtpCryptoSuites
    {
        public const int AES_CM_128_HMAC_SHA1_80 = 0xFF0001;
        public const int AES_CM_128_HMAC_SHA1_32 = 0xFF0002;
        public const int F8_128_HMAC_SHA1_80 = 0xFF0003;
        public const int SEED_CTR_128_HMAC_SHA1_80 = 0xFF0004;
        public const int SEED_128_CCM_80 = 0xFF0005;
        public const int SEED_128_GCM_96 = 0xFF0006;
        public const int AES_192_CM_HMAC_SHA1_80 = 0xFF0007;
        public const int AES_192_CM_HMAC_SHA1_32 = 0xFF0008;
        public const int AES_256_CM_HMAC_SHA1_80 = 0xFF0009;
        public const int AES_256_CM_HMAC_SHA1_32 = 0xFF000A;
        public const int AEAD_AES_128_GCM = 0xFF000B;
        public const int AEAD_AES_256_GCM = 0xFF000C;
    }

    public static class SrtpProtocol
    {
        public static readonly Dictionary<int, SrtpProtectionProfileConfiguration> SrtpCryptoSuites;

        static SrtpProtocol()
        {
            // see https://www.iana.org/assignments/sdp-security-descriptions/sdp-security-descriptions.xhtml
            SrtpCryptoSuites = new Dictionary<int, SrtpProtectionProfileConfiguration>()
            {
                { SRTP.SrtpCryptoSuites.AEAD_AES_256_GCM, new SrtpProtectionProfileConfiguration(SrtpCiphers.AEAD_AES_256_GCM, 256, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },
                { SRTP.SrtpCryptoSuites.AEAD_AES_128_GCM, new SrtpProtectionProfileConfiguration(SrtpCiphers.AEAD_AES_128_GCM, 128, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },

                // https://datatracker.ietf.org/doc/html/rfc6188
                { SRTP.SrtpCryptoSuites.AES_256_CM_HMAC_SHA1_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { SRTP.SrtpCryptoSuites.AES_256_CM_HMAC_SHA1_32, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
                { SRTP.SrtpCryptoSuites.AES_192_CM_HMAC_SHA1_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_192_CM, 192, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { SRTP.SrtpCryptoSuites.AES_192_CM_HMAC_SHA1_32, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_192_CM, 192, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },

                { SRTP.SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { SRTP.SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_32, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },

                { SRTP.SrtpCryptoSuites.F8_128_HMAC_SHA1_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.AES_128_F8, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },

                // https://datatracker.ietf.org/doc/html/rfc5669
                { SRTP.SrtpCryptoSuites.SEED_CTR_128_HMAC_SHA1_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.SEED_128_CTR, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { SRTP.SrtpCryptoSuites.SEED_128_CCM_80, new SrtpProtectionProfileConfiguration(SrtpCiphers.SEED_128_CCM, 128, 96, int.MaxValue, SrtpAuth.NONE, 0, 80) },
                { SRTP.SrtpCryptoSuites.SEED_128_GCM_96, new SrtpProtectionProfileConfiguration(SrtpCiphers.SEED_128_GCM, 128, 96, int.MaxValue, SrtpAuth.NONE, 0, 96) },
            };
        }
    }
}
