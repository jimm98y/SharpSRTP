using Org.BouncyCastle.Crypto.Engines;

namespace SharpSRTP.SRTP.Encryption
{
    public static class NULL
    {
        public static void Encrypt(AesEngine aes, byte[] payload, int offset, int length, byte[] iv)
        {
            // NULL encryption is equivalent to XOR with zeroes, so do nothing
        }
    }
}
