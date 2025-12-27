using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public static class SRTPProtocol
    {
        public static readonly Dictionary<int, SRTPProtectionProfile> ProtectionProfiles;

        static SRTPProtocol()
        {
            ProtectionProfiles = new Dictionary<int, SRTPProtectionProfile>()
            {
                // AES256 CM is specified in RFC 6188, but not included in IANA DTLS-SRTP registry https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1
                // https://www.rfc-editor.org/rfc/rfc6188
                // AES192 CM is not supported in DTLS-SRTP
                // AES256 CM was removed in Draft 4 of RFC 5764
                // https://author-tools.ietf.org/iddiff?url1=draft-ietf-avt-dtls-srtp-04&url2=draft-ietf-avt-dtls-srtp-03&difftype=--html
                { ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_80, new SRTPProtectionProfile(SRTPCiphers.AES_256_CM, 256, 112, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_32, new SRTPProtectionProfile(SRTPCiphers.AES_256_CM, 256, 112, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 32) },

                // https://datatracker.ietf.org/doc/html/rfc5764#section-9
                { ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, new SRTPProtectionProfile(SRTPCiphers.AES_128_CM, 128, 112, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, new SRTPProtectionProfile(SRTPCiphers.AES_128_CM, 128, 112, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 32) },
                { ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, new SRTPProtectionProfile(SRTPCiphers.NULL, 0, 0, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 80) },
                { ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, new SRTPProtectionProfile(SRTPCiphers.NULL, 0, 0, int.MaxValue, SRTPAuth.HMAC_SHA1, 160, 32) },
            };
        }

        public static SRTPKeys GenerateMasterKeys(int profile, SecurityParameters dtlsSecurityParameters)
        {
            // SRTP key derivation as described here https://datatracker.ietf.org/doc/html/rfc5764
            var srtpSecurityParams = ProtectionProfiles[profile];

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

            SRTPKeys keys = new SRTPKeys(profile);

            Buffer.BlockCopy(shared_secret, 0, keys.ClientWriteMasterKey, 0, keys.ClientWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length, keys.ServerWriteMasterKey, 0, keys.ServerWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length, keys.ClientWriteMasterSalt, 0, keys.ClientWriteMasterSalt.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length + keys.ClientWriteMasterSalt.Length, keys.ServerWriteMasterSalt, 0, keys.ServerWriteMasterSalt.Length);

            return keys;
        }

        public static byte[] GenerateSessionKey(byte[] masterKey, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] iv = GenerateSessionIV(masterSalt, index, kdr, (byte)label);

            var aes = new AesEngine();
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(masterKey));

            byte[] key = new byte[length];
            AESCTR.Encrypt(aes, key, 0, length, iv);           

            return key;
        }

        public static ulong GenerateRTPIndex(uint ROC, ushort SEQ)
        {
            // RFC 3711 - 3.3.1
            // i = 2 ^ 16 * ROC + SEQ
            return ((ulong)ROC << 16) | SEQ;
        }

        public static uint DetermineRTPIndex(uint s_l, ushort SEQ, ulong ROC)
        {
            // RFC 3711 - Appendix A
            ulong v;
            if (s_l < 32768)
            {
                if (SEQ - s_l > 32768)
                    v = (ROC - 1) % 4294967296L;
                else
                    v = ROC;
            }
            else
            {
                if (s_l - 32768 > SEQ)
                    v = (ROC + 1) % 4294967296L;
                else
                    v = ROC;
            }
            return (uint)(SEQ + v * 65536U);
        }

        public static byte[] GenerateMessageIV(byte[] salt, uint ssrc, ulong index)
        {
            // RFC 3711 - 4.1.1
            // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
            byte[] iv = new byte[16];

            Array.Copy(salt, 0, iv, 0, 14);

            iv[4] ^= (byte)((ssrc >> 24) & 0xFF);
            iv[5] ^= (byte)((ssrc >> 16) & 0xFF);
            iv[6] ^= (byte)((ssrc >> 8) & 0xFF);
            iv[7] ^= (byte)(ssrc & 0xFF);

            iv[8] ^= (byte)((index >> 40) & 0xFF);
            iv[9] ^= (byte)((index >> 32) & 0xFF);
            iv[10] ^= (byte)((index >> 24) & 0xFF);
            iv[11] ^= (byte)((index >> 16) & 0xFF);
            iv[12] ^= (byte)((index >> 8) & 0xFF);
            iv[13] ^= (byte)(index & 0xFF);

            iv[14] = 0;
            iv[15] = 0;

            return iv;
        }

        private static ulong DIV(ulong x, ulong y)
        {
            if (y == 0)
                return 0;
            else
                return x / y;   
        }

        public static byte[] GenerateSessionIV(byte[] masterSalt, ulong index, ulong kdr, byte label)
        {
            // RFC 3711 - 4.1.1
            // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
            byte[] iv = new byte[16];

            ulong r = DIV(index, kdr);
            ulong keyId = ((ulong)label << 48) | r;

            Array.Copy(masterSalt, 0, iv, 0, 14);

            iv[7] ^= (byte)((keyId >> 48) & 0xFF);
            iv[8] ^= (byte)((keyId >> 40) & 0xFF);
            iv[9] ^= (byte)((keyId >> 32) & 0xFF);
            iv[10] ^= (byte)((keyId >> 24) & 0xFF);
            iv[11] ^= (byte)((keyId >> 16) & 0xFF);
            iv[12] ^= (byte)((keyId >> 8) & 0xFF);
            iv[13] ^= (byte)(keyId & 0xFF);

            iv[14] = 0;
            iv[15] = 0;

            return iv;
        }

        public static byte[] GenerateAuthTag(HMac hmac, byte[] payload, int offset, int length)
        {
            hmac.BlockUpdate(payload, offset, length);

            byte[] output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);

            return output;
        }
    }
}
