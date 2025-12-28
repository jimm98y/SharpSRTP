using Org.BouncyCastle.Crypto.Engines;
using System;

namespace SharpSRTP.SRTP.Encryption
{
    public static class AESCM
    {
        public const int AES_BLOCK_SIZE = 16;

        public static byte[] GenerateSessionKeyIV(byte[] masterSalt, ulong index, ulong kdr, byte label)
        {
            byte[] iv = new byte[16];

            // RFC 3711 - 4.3.1
            // Key derivation SHALL be defined as follows in terms of<label>, an
            // 8 - bit constant(see below), master_salt and key_derivation_rate, as
            // determined in the cryptographic context, and index, the packet index
            // (i.e., the 48 - bit ROC || SEQ for SRTP):

            // *Let r = index DIV key_derivation_rate(with DIV as defined above).
            ulong r = DIV(index, kdr);

            // *Let key_id = < label > || r.
            ulong keyId = ((ulong)label << 48) | r;

            // *Let x = key_id XOR master_salt, where key_id and master_salt are
            //  aligned so that their least significant bits agree(right-
            //  alignment).
            Array.Copy(masterSalt, 0, iv, 0, masterSalt.Length);

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

        private static ulong DIV(ulong x, ulong y)
        {
            if (y == 0)
                return 0;
            else
                return x / y;
        }

        public static byte[] GenerateMessageKeyIV(byte[] salt, uint ssrc, ulong index)
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
