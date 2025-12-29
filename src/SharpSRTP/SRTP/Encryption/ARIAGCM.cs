using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;

namespace SharpSRTP.SRTP.Encryption
{
    public static class ARIAGCM
    {
        public static void Encrypt(GcmBlockCipher cipher, byte[] payload, int offset, int length, byte[] iv, byte[] K_e, int N_tag, byte[] associatedData)
        {
            int payloadSize = length - offset;

            int expectedLength = cipher.GetOutputSize(payloadSize);
            if (offset + expectedLength > payload.Length)
                throw new ArgumentOutOfRangeException("Payload is too small!");

            var parameters = new AeadParameters(new KeyParameter(K_e), N_tag << 3, iv, associatedData);
            cipher.Init(true, parameters);

            int len = cipher.ProcessBytes(payload, offset, payloadSize, payload, offset);
            cipher.DoFinal(payload, offset + len);
        }

        public static byte[] GenerateMessageKeyIV(byte[] k_s, uint ssrc, ulong index)
        {
            byte[] iv = new byte[12];
            Buffer.BlockCopy(k_s, 0, iv, 0, 12);

            iv[2] ^= (byte)((ssrc >> 24) & 0xFF);
            iv[3] ^= (byte)((ssrc >> 16) & 0xFF);
            iv[4] ^= (byte)((ssrc >> 8) & 0xFF);
            iv[5] ^= (byte)(ssrc & 0xFF);
            iv[6] ^= (byte)((index >> 40) & 0xFF);
            iv[7] ^= (byte)((index >> 32) & 0xFF);
            iv[8] ^= (byte)((index >> 24) & 0xFF);
            iv[9] ^= (byte)((index >> 16) & 0xFF);
            iv[10] ^= (byte)((index >> 8) & 0xFF);
            iv[11] ^= (byte)(index & 0xFF);

            return iv;
        }
    }
}
