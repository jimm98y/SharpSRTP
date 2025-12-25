namespace SharpSRTP.SRTP
{
    public static class SrtpCiphers
    {
        public const int NULL = 0;
        public const int AES_128_CM = 1;
        public const int AES_256_CM = 2;
    }

    public static class SrtpAuth
    {
        public const int NONE = 0;
        public const int HMAC_SHA1 = 1;
    }

    public class SrtpProtectionProfile
    {
        public SrtpProtectionProfile(int cipher, int cipherKeyLength, int cipherSaltLength, int maximumLifetime, int authFunction, int authKeyLength, int authTagLength)
        {
            Cipher = cipher;
            CipherKeyLength = cipherKeyLength;
            CipherSaltLength = cipherSaltLength;
            MaximumLifetime = maximumLifetime;
            AuthFunction = authFunction;
            AuthKeyLength = authKeyLength;
            AuthTagLength = authTagLength;
        }

        public int Cipher { get; set; }
        public int CipherKeyLength { get; set; }
        public int CipherSaltLength { get; set; }
        public int MaximumLifetime { get; set; }
        public int AuthFunction { get; set; }
        public int AuthKeyLength { get; set; }
        public int AuthTagLength { get; set; }
    }
}
