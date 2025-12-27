using System;
using System.Collections.Generic;
using System.Text;

namespace SharpSRTP.SRTP
{
    public class SRTPKeys
    {
        private readonly int _protectionProfile;
        public int ProtectionProfile { get { return _protectionProfile; } }

        private byte[] _client_write_SRTP_master_key = null;
        private byte[] _server_write_SRTP_master_key = null;
        private byte[] _client_write_SRTP_master_salt = null;
        private byte[] _server_write_SRTP_master_salt = null;

        public byte[] ClientWriteMasterKey { get { return _client_write_SRTP_master_key; } }
        public byte[] ClientWriteMasterSalt { get { return _client_write_SRTP_master_salt; } }
        public byte[] ServerWriteMasterKey { get { return _server_write_SRTP_master_key; } }
        public byte[] ServerWriteMasterSalt { get { return _server_write_SRTP_master_salt; } }

        public SRTPKeys(int protectionProfile)
        {
            _protectionProfile = protectionProfile;

            var srtpSecurityParams = SRTProtocol.ProtectionProfiles[_protectionProfile];
            int cipherKeyLen = srtpSecurityParams.CipherKeyLength >> 3;
            int cipherSaltLen = srtpSecurityParams.CipherSaltLength >> 3;
            _client_write_SRTP_master_key = new byte[cipherKeyLen];
            _server_write_SRTP_master_key = new byte[cipherKeyLen];
            _client_write_SRTP_master_salt = new byte[cipherSaltLen];
            _server_write_SRTP_master_salt = new byte[cipherSaltLen];
        }
    }
}
