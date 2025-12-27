using Org.BouncyCastle.Crypto.Engines;
using System;

namespace SharpSRTP.SRTP
{
    public static class AESCTR
    {
        private const int AES_BLOCK_SIZE = 16;

        public static void Encrypt(AesEngine aes, byte[] payload, int offset, int length, byte[] iv)
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
        public static void EncryptBlock(AesEngine aes, byte[] payload, byte[] iv, int blockNo)
        {
            if (payload.Length > AES_BLOCK_SIZE)
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
    }
}
