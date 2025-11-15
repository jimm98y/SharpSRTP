using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public class SrtpKeyGenerator
    {
        private readonly int _protectionProfile;

        private static readonly Dictionary<int, SrtpProtectionProfile> _protectionProfiles;

        private byte[] _client_write_SRTP_master_key = null;
        private byte[] _server_write_SRTP_master_key = null;
        private byte[] _client_write_SRTP_master_salt = null;
        private byte[] _server_write_SRTP_master_salt = null;

        public byte[] ClientWriteMasterKey { get { return _client_write_SRTP_master_key; } }
        public byte[] ClientWriteMasterSalt { get { return _client_write_SRTP_master_salt; } }
        public byte[] ServerWriteMasterKey { get { return _server_write_SRTP_master_key; } }
        public byte[] ServerWriteMasterSalt { get { return _server_write_SRTP_master_salt; } }

        static SrtpKeyGenerator()
        {
            _protectionProfiles = new Dictionary<int, SrtpProtectionProfile>()
            {
                // https://datatracker.ietf.org/doc/html/rfc5764#section-9
                { Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.AES_128_CM, 128, 112, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
                { Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 80) },
                { Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, new SrtpProtectionProfile(SrtpCiphers.NULL, 0, 0, int.MaxValue, SrtpAuth.HMAC_SHA1, 160, 32) },
            };
        }

        public SrtpKeyGenerator(int profile)
        {
            _protectionProfile = profile;

            var srtpSecurityParams = _protectionProfiles[_protectionProfile];
            int cipherKeyLen = srtpSecurityParams.CipherKeyLength >> 3;
            int cipherSaltLen = srtpSecurityParams.CipherSaltLength >> 3;
            _client_write_SRTP_master_key = new byte[cipherKeyLen];
            _server_write_SRTP_master_key = new byte[cipherKeyLen];
            _client_write_SRTP_master_salt = new byte[cipherSaltLen];
            _server_write_SRTP_master_salt = new byte[cipherSaltLen];
        }

        public void Generate(SecurityParameters dtlsSecurityParameters)
        {

            // SRTP key derivation as described here https://datatracker.ietf.org/doc/html/rfc5764
            var srtpSecurityParams = _protectionProfiles[_protectionProfile];

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

            Buffer.BlockCopy(shared_secret, 0, _client_write_SRTP_master_key, 0, _client_write_SRTP_master_key.Length);
            Buffer.BlockCopy(shared_secret, _client_write_SRTP_master_key.Length, _server_write_SRTP_master_key, 0, _server_write_SRTP_master_key.Length);
            Buffer.BlockCopy(shared_secret, _client_write_SRTP_master_key.Length + _server_write_SRTP_master_key.Length, _client_write_SRTP_master_salt, 0, _client_write_SRTP_master_salt.Length);
            Buffer.BlockCopy(shared_secret, _client_write_SRTP_master_key.Length + _server_write_SRTP_master_key.Length + _client_write_SRTP_master_salt.Length, _server_write_SRTP_master_salt, 0, _server_write_SRTP_master_salt.Length);

            Console.WriteLine("Server 'client_write_SRTP_master_key': " + Hex.ToHexString(_client_write_SRTP_master_key));
            Console.WriteLine("Server 'server_write_SRTP_master_key': " + Hex.ToHexString(_server_write_SRTP_master_key));
            Console.WriteLine("Server 'client_write_SRTP_master_salt': " + Hex.ToHexString(_client_write_SRTP_master_salt));
            Console.WriteLine("Server 'server_write_SRTP_master_salt': " + Hex.ToHexString(_server_write_SRTP_master_salt));
        }
    }
}
