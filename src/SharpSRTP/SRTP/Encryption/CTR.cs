// SharpSRTP
// Copyright (C) 2025 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;
#if NET8_0_OR_GREATER
using Bytes = System.Span<byte>;
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
#else
using Bytes = byte[];
using ReadOnlyBytes = byte[];
#endif

namespace SharpSRTP.SRTP.Encryption
{
    public static class CTR
    {
        public const int BLOCK_SIZE = 16;

        public static void GenerateSessionKeyIV(ReadOnlyMemory<byte> masterSalt, ulong index, ulong kdr, byte label, Span<byte> iv)
        {
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
            masterSalt.Span.CopyTo(iv);

            // XOR index at offset 7 (6 bytes for 48-bit index)
            BinaryExtensions.Xor64(iv.Slice(6, 8), (keyId & 0x00FF_FFFF_FFFF_FFFF));

            iv[14] = 0;
            iv[15] = 0;
        }

        private static ulong DIV(ulong x, ulong y)
        {
            if (y == 0)
            {
                return 0;
            }
            else
            {
                return x / y;
            }
        }

        public static byte[] GenerateMessageKeyIV(ReadOnlySpan<byte> salt, uint ssrc, ulong index)
        {
            // RFC 3711 - 4.1.1
            // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
            byte[] iv = GC.AllocateUninitializedArray<byte>(16);

            salt.Slice(0, 14).CopyTo(iv);

            // XOR ssrc at offset 4 (3 bytes for 48-bit index)
            BinaryExtensions.Xor32(iv.AsSpan(4, 4), ssrc);

            // XOR index at offset 8 (6 bytes for 48-bit index)
            BinaryExtensions.Xor64(iv.AsSpan(6, 8), index & 0x0000_FFFF_FFFF_FFFF);

            iv[14] = 0;
            iv[15] = 0;

            return iv;
        }

        public static void Encrypt(IBlockCipher engine, Span<byte> payload, int offset, int length, Bytes iv)
        {
            int payloadSize = length - offset;
            byte[] cipher = ArrayPool<byte>.Shared.Rent(payloadSize);

            try
            {
                int blockNo = 0;
                for (int i = 0; i < payloadSize / BLOCK_SIZE; i++)
                {
                    iv[14] = (byte)((i >> 8) & 0xff);
                    iv[15] = (byte)(i & 0xff);
#if NET8_0_OR_GREATER
                    engine.ProcessBlock(iv, cipher.AsSpan(BLOCK_SIZE * blockNo));
#else
                    engine.ProcessBlock(iv, 0, cipher, BLOCK_SIZE * blockNo);
#endif
                    blockNo++;
                }

                if (payloadSize % BLOCK_SIZE != 0)
                {
                    iv[14] = (byte)((blockNo >> 8) & 0xff);
                    iv[15] = (byte)(blockNo & 0xff);
                    byte[] lastBlock = GC.AllocateUninitializedArray<byte>(BLOCK_SIZE);
#if NET8_0_OR_GREATER
                    engine.ProcessBlock(iv, lastBlock);
#else
                    engine.ProcessBlock(iv, 0, lastBlock, 0);
#endif
                    Buffer.BlockCopy(lastBlock, 0, cipher, BLOCK_SIZE * blockNo, payloadSize % BLOCK_SIZE);
                }

                BinaryExtensions.Xor(
                    payload.Slice(offset, payloadSize),
                    cipher.AsSpan(0, payloadSize));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(cipher);
            }
        }
    }
}
