using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace SharpSRTP.SRTP.Encryption
{
    public static class AESGCM
    {
        public const int AES_BLOCK_SIZE = 16;

        public static void Encrypt(AesEngine aes, byte[] payload, int offset, int length, byte[] iv)
        {
            throw new NotImplementedException();
        }
    }
}
