using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Org.BouncyCastle.Tls
{
    /// <summary>
    /// Currently registered DTLS-SRTP profiles: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1
    /// </summary>
    public abstract class ExtendedSrtpProtectionProfile : SrtpProtectionProfile
    {
        // TODO: Remove this once BouncyCastle adds the constants
        public const int DRAFT_SRTP_AES256_CM_SHA1_80 = 0x0003;
        public const int DRAFT_SRTP_AES256_CM_SHA1_32 = 0x0004;
        public const int DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 0x0009;
        public const int DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 0x000A;
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_80 = 0x000B;
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_32 = 0x000C;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_80 = 0x000D;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_32 = 0x000E;
        public const int SRTP_AEAD_ARIA_128_GCM = 0x000F;
        public const int SRTP_AEAD_ARIA_256_GCM = 0x0010;
    }
}

namespace SharpSRTP.SRTP
{
    public class SrtpKeys
    {
        private readonly int _protectionProfile;

        private byte[] _client_write_SRTP_master_key = null;
        private byte[] _server_write_SRTP_master_key = null;
        private byte[] _client_write_SRTP_master_salt = null;
        private byte[] _server_write_SRTP_master_salt = null;

        public byte[] ClientWriteMasterKey { get { return _client_write_SRTP_master_key; } }
        public byte[] ClientWriteMasterSalt { get { return _client_write_SRTP_master_salt; } }
        public byte[] ServerWriteMasterKey { get { return _server_write_SRTP_master_key; } }
        public byte[] ServerWriteMasterSalt { get { return _server_write_SRTP_master_salt; } }

        public SrtpKeys(int profile)
        {
            _protectionProfile = profile;

            var srtpSecurityParams = SrtpKeyGenerator.ProtectionProfiles[_protectionProfile];
            int cipherKeyLen = srtpSecurityParams.CipherKeyLength >> 3;
            int cipherSaltLen = srtpSecurityParams.CipherSaltLength >> 3;
            _client_write_SRTP_master_key = new byte[cipherKeyLen];
            _server_write_SRTP_master_key = new byte[cipherKeyLen];
            _client_write_SRTP_master_salt = new byte[cipherSaltLen];
            _server_write_SRTP_master_salt = new byte[cipherSaltLen];
        }
    }

    public static class SrtpKeyGenerator
    {
        private const int AES_BLOCK_SIZE = 16;

        public static readonly Dictionary<int, SrtpProtectionProfile> ProtectionProfiles;

        static SrtpKeyGenerator()
        {
            ProtectionProfiles = new Dictionary<int, SrtpProtectionProfile>()
            {
                // AES256 CM is specified in RFC 6188, but not included in IANA DTLS-SRTP registry https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1
                // https://www.rfc-editor.org/rfc/rfc6188
                // AES192 CM is not supported in DTLS-SRTP
                // AES256 CM was removed in Draft 4 of RFC 5764
                // https://author-tools.ietf.org/iddiff?url1=draft-ietf-avt-dtls-srtp-04&url2=draft-ietf-avt-dtls-srtp-03&difftype=--html
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.DRAFT_SRTP_AES256_CM_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.AES_256_CM, 256, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },

                // https://datatracker.ietf.org/doc/html/rfc5764#section-9
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
            };
        }

        public static SrtpKeys GenerateMasterKeys(int profile, SecurityParameters dtlsSecurityParameters)
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

            SrtpKeys keys = new SrtpKeys(profile);

            Buffer.BlockCopy(shared_secret, 0, keys.ClientWriteMasterKey, 0, keys.ClientWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length, keys.ServerWriteMasterKey, 0, keys.ServerWriteMasterKey.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length, keys.ClientWriteMasterSalt, 0, keys.ClientWriteMasterSalt.Length);
            Buffer.BlockCopy(shared_secret, keys.ClientWriteMasterKey.Length + keys.ServerWriteMasterKey.Length + keys.ClientWriteMasterSalt.Length, keys.ServerWriteMasterSalt, 0, keys.ServerWriteMasterSalt.Length);

            //Console.WriteLine("Server 'client_write_SRTP_master_key': " + Hex.ToHexString(keys.ClientWriteMasterKey));
            //Console.WriteLine("Server 'server_write_SRTP_master_key': " + Hex.ToHexString(keys.ServerWriteMasterKey));
            //Console.WriteLine("Server 'client_write_SRTP_master_salt': " + Hex.ToHexString(keys.ClientWriteMasterSalt));
            //Console.WriteLine("Server 'server_write_SRTP_master_salt': " + Hex.ToHexString(keys.ServerWriteMasterSalt));

            return keys;
        }

        public static byte[] GenerateSessionKey(byte[] masterKey, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] iv = GenerateSessionIV(masterSalt, index, kdr, (byte)label);

            var aes = new AesEngine();
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(masterKey));

            byte[] key = new byte[length];
            EncryptAESCTR(aes, key, 0, length, iv);           

            return key;
        }

        public static ulong GenerateRTPIndex(uint ROC, ushort SEQ)
        {
            // RFC 3711 - 3.3.1
            // i = 2 ^ 16 * ROC + SEQ
            return ((ulong)ROC << 16) | SEQ;
        }

        public static ulong DetermineRTPIndex(uint s_l, ushort SEQ, ulong ROC)
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
            return SEQ + v * 65536U;
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

        public static void EncryptAESCTR(AesEngine aes, byte[] payload, int offset, int length, byte[] iv)
        {
            int payloadSize = length - offset;
            byte[] cipher = new byte[payloadSize];

            int blockNo = 0;
            for (int i = 0; i < payloadSize / AES_BLOCK_SIZE; i++)
            {
                iv[14] = (byte)((i >> 8) & 0xff);
                iv[15] = (byte)(i & 0xff);
                aes.ProcessBlock(iv, 0, cipher, AES_BLOCK_SIZE * blockNo);
                blockNo++;
            }

            if (payloadSize % AES_BLOCK_SIZE != 0)
            {
                iv[14] = (byte)((blockNo >> 8) & 0xff);
                iv[15] = (byte)(blockNo & 0xff);
                byte[] lastBlock = new byte[AES_BLOCK_SIZE];
                aes.ProcessBlock(iv, 0, lastBlock, 0);
                Buffer.BlockCopy(lastBlock, 0, cipher, AES_BLOCK_SIZE * blockNo, payloadSize % AES_BLOCK_SIZE);
            }

            for (int i = 0; i < payloadSize; i++)
            {
                payload[offset + i] ^= cipher[i];
            }
        }

        // currently only used by tests
        public static void EncryptBlockAESCTR(AesEngine aes, byte[] payload, byte[] iv, int blockNo)
        {
            if(payload.Length > AES_BLOCK_SIZE)
                throw new ArgumentException("Payload length must not be larger than AES block size.");

            byte[] cipher = new byte[AES_BLOCK_SIZE];

            iv[14] = (byte)((blockNo >> 8) & 0xff);
            iv[15] = (byte)(blockNo & 0xff);
            aes.ProcessBlock(iv, 0, cipher, 0);

            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] ^= cipher[i];
            }
        }

        public static uint RtpReadSsrc(byte[] rtpPacket)
        {
            return (uint)((rtpPacket[8] << 24) | (rtpPacket[9] << 16) | (rtpPacket[10] << 8) | rtpPacket[11]);
        }

        public static ushort RtpReadSequenceNumber(byte[] rtpPacket)
        {
            return (ushort)((rtpPacket[2] << 8) | rtpPacket[3]);
        }

        public static int RtpReadHeaderLen(byte[] payload)
        {
            int length = 12 + 4 * (payload[0] & 0xf);
            if ((payload[0] & 0x10) == 0x10)
            {
                int extLen = (payload[length + 2] << 8) | payload[length + 3];
                length += 4 + extLen;
            }
            return length;
        }

        public static uint RtcpReadSsrc(byte[] rtcpPacket)
        {
            return (uint)((rtcpPacket[4] << 24) | (rtcpPacket[5] << 16) | (rtcpPacket[6] << 8) | rtcpPacket[7]);
        }

        public static int RtcpReadHeaderLen(byte[] rtcpPacket)
        {
            return 8;
        }

        public static uint SrtcpReadIndex(byte[] srtcpPacket, int authTagLen)
        {
            int index = srtcpPacket.Length - authTagLen - 4;
            return (uint)((srtcpPacket[index] << 24) | (srtcpPacket[index + 1] << 16) | (srtcpPacket[index + 2] << 8) | srtcpPacket[index + 3]);
        }
    }
}
