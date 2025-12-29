using System;

namespace SharpSRTP.SRTP
{
    public class SrtpKeys
    {
        public int ProtectionProfile { get; }
        public byte[] Mki { get; }

        public byte[] ClientWriteMasterKey { get; }
        public byte[] ClientWriteMasterSalt { get; }
        public byte[] ServerWriteMasterKey { get; }
        public byte[] ServerWriteMasterSalt { get; }

        public SrtpKeys(int protectionProfile, byte[] mki = null)
        {
            if (!DtlsSrtpProtocol.DtlsProtectionProfiles.ContainsKey(protectionProfile))
                throw new NotSupportedException($"Unsupported protectionProfile {protectionProfile}");

            SrtpProtectionProfileConfiguration srtpSecurityParams = DtlsSrtpProtocol.DtlsProtectionProfiles[protectionProfile];

            this.ProtectionProfile = protectionProfile;
            this.Mki = mki;

            int cipherKeyLen = srtpSecurityParams.CipherKeyLength >> 3;
            int cipherSaltLen = srtpSecurityParams.CipherSaltLength >> 3;

            this.ClientWriteMasterKey = new byte[cipherKeyLen];
            this.ClientWriteMasterSalt = new byte[cipherSaltLen];
            this.ServerWriteMasterKey = new byte[cipherKeyLen];
            this.ServerWriteMasterSalt = new byte[cipherSaltLen];
        }
    }
}
