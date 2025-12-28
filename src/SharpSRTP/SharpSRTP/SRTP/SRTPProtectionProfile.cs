namespace SharpSRTP.SRTP
{
    public enum SRTPCiphers
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

    public enum SRTPAuth
    {
        NONE = 0,
        HMAC_SHA1 = 1
    }

    public class SRTPProtectionProfile
    {
        public SRTPProtectionProfile(SRTPCiphers cipher, int cipherKeyLength, int cipherSaltLength, int maximumLifetime, SRTPAuth auth, int authKeyLength, int authTagLength, int srtpPrefixLength = 0)
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

        public SRTPCiphers Cipher { get; set; }
        public int CipherKeyLength { get; set; }
        public int CipherSaltLength { get; set; }
        public int MaximumLifetime { get; set; }
        public SRTPAuth Auth { get; set; }
        public int AuthKeyLength { get; set; }
        public int AuthTagLength { get; set; }
        public int SrtpPrefixLength { get; set; }
    }
}
