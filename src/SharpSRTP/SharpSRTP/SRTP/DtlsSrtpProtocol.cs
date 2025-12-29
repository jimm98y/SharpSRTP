using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public enum SrtpCiphers
    {
        NULL = 0,
        AES_128_CM = 1,
        AES_128_F8 = 2,
        AES_256_CM = 3,
        AEAD_AES_128_GCM = 4,
        AEAD_AES_256_GCM = 5,
        ARIA_128_CTR = 6,
        ARIA_256_CTR = 7,
        AEAD_ARIA_128_GCM = 8,
        AEAD_ARIA_256_GCM = 9,
        //DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 10,
        //DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 11
    }

    public enum SrtpAuth
    {
        NONE = 0,
        HMAC_SHA1 = 1
    }

    public class SrtpProtectionProfile
    {
        public SrtpProtectionProfile(SrtpCiphers cipher, int cipherKeyLength, int cipherSaltLength, int maximumLifetime, SrtpAuth auth, int authKeyLength, int authTagLength, int srtpPrefixLength = 0)
        {
            Cipher = cipher;
            CipherKeyLength = cipherKeyLength;
            CipherSaltLength = cipherSaltLength;
            MaximumLifetime = maximumLifetime;
            Auth = auth;
            AuthKeyLength = authKeyLength;
            AuthTagLength = authTagLength;
            SrtpPrefixLength = srtpPrefixLength;
        }

        public SrtpCiphers Cipher { get; set; }
        public int CipherKeyLength { get; set; }
        public int CipherSaltLength { get; set; }
        public int MaximumLifetime { get; set; }
        public SrtpAuth Auth { get; set; }
        public int AuthKeyLength { get; set; }
        public int AuthTagLength { get; set; }
        public int SrtpPrefixLength { get; set; }
    }

    public static class DtlsSrtpProtocol
    {
        public static readonly Dictionary<int, SrtpProtectionProfile> DtlsProtectionProfiles;

        static DtlsSrtpProtocol()
        {
            DtlsProtectionProfiles = new Dictionary<int, SrtpProtectionProfile>()
            {
                // https://datatracker.ietf.org/doc/html/rfc8269
                { ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_256_GCM, new SrtpProtectionProfile(SrtpCiphers.AEAD_ARIA_256_GCM, 256, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },
                { ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM, new SrtpProtectionProfile(SrtpCiphers.AEAD_ARIA_128_GCM, 128, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },
                { ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.ARIA_256_CTR, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.ARIA_256_CTR, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
                { ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.ARIA_128_CTR, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.ARIA_128_CTR, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },

                // https://datatracker.ietf.org/doc/html/rfc7714
                { ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_256_GCM, new SrtpProtectionProfile(SrtpCiphers.AEAD_AES_256_GCM, 256, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },
                { ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, new SrtpProtectionProfile(SrtpCiphers.AEAD_AES_128_GCM, 128, 96, int.MaxValue, SrtpAuth.NONE, 0, 128) },

                // AES256 CM is specified in RFC 6188, but not included in IANA DTLS-SRTP registry https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1
                // https://www.rfc-editor.org/rfc/rfc6188
                // AES192 CM is not supported in DTLS-SRTP
                // AES256 CM was removed in Draft 4 of RFC 5764
                // https://author-tools.ietf.org/iddiff?url1=draft-ietf-avt-dtls-srtp-04&url2=draft-ietf-avt-dtls-srtp-03&difftype=--html
                { ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },

                // https://datatracker.ietf.org/doc/html/rfc5764#section-9
                { ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
                { ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
            };
        }

        public static SrtpKeys GenerateMasterKeys(int protectionProfile, byte[] mki, SecurityParameters dtlsSecurityParameters, bool requireExtendedMasterSecret = true)
        {
            // verify that we have extended master secret before computing the keys
            if(!dtlsSecurityParameters.IsExtendedMasterSecret && requireExtendedMasterSecret)
            {
                throw new InvalidOperationException();
            }

            // SRTP key derivation as described here https://datatracker.ietf.org/doc/html/rfc5764
            var srtpSecurityParams = DtlsProtectionProfiles[protectionProfile];

            // 2 * (SRTPSecurityParams.master_key_len + SRTPSecurityParams.master_salt_len) bytes of data
            int shared_secret_length = 2 * (srtpSecurityParams.CipherKeyLength + srtpSecurityParams.CipherSaltLength); // in bits

            // EXTRACTOR-dtls_srtp https://datatracker.ietf.org/doc/html/rfc5705

            // TODO: If context is provided, it computes:
            /*
            PRF(SecurityParameters.master_secret, label,
                SecurityParameters.client_random +
                SecurityParameters.server_random +
                context_value_length + context_value
                )[length]
            */

            // derive shared secret
            /*
            PRF(SecurityParameters.master_secret, label,
               SecurityParameters.client_random +
               SecurityParameters.server_random
               )[length]
             */
            byte[] shared_secret = TlsUtilities.Prf(
                dtlsSecurityParameters,
                dtlsSecurityParameters.MasterSecret,
                ExporterLabel.dtls_srtp, // The exporter label for this usage is "EXTRACTOR-dtls_srtp"
                dtlsSecurityParameters.ClientRandom.Concat(dtlsSecurityParameters.ServerRandom).ToArray(),
                shared_secret_length >> 3
                ).Extract();

            SrtpKeys keys = new SrtpKeys(protectionProfile, mki);

            Buffer.BlockCopy(shared_secret, 0, keys.ClientWriteMasterKey, 0, keys.ClientWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length, keys.ServerWriteMasterKey, 0, keys.ServerWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length, keys.ClientWriteMasterSalt, 0, keys.ClientWriteMasterSalt.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length + keys.ClientWriteMasterSalt.Length, keys.ServerWriteMasterSalt, 0, keys.ServerWriteMasterSalt.Length);

            return keys;
        }
    }
}
