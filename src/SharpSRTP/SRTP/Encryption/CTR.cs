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
using System.Buffers.Binary;
using System.Numerics;

namespace SharpSRTP.SRTP.Encryption
{
    public static class CTR
    {
        public const int BLOCK_SIZE = 16;

        public static void GenerateSessionKeyIV(Span<byte> iv, ReadOnlySpan<byte> masterSalt, ulong index, ulong kdr, byte label)
        {
            if (iv.Length != BLOCK_SIZE)
                Throw.ArgumentException($"IV buffer must be exactly {BLOCK_SIZE} bytes", nameof(iv));

            // RFC 3711 - 4.3.1
            // Key derivation SHALL be defined as follows in terms of<label>, an
            // 8 - bit constant(see below), master_salt and key_derivation_rate, as
            // determined in the cryptographic context, and index, the packet index
            // (i.e., the 48 - bit ROC || SEQ for SRTP):

            // *Let r = index DIV key_derivation_rate(with DIV as defined above).
            var r = DIV(index, kdr);

            // *Let key_id = < label > || r.
            var keyId = ((ulong)label << 48) | r;

            // *Let x = key_id XOR master_salt, where key_id and master_salt are
            //  aligned so that their least significant bits agree(right-
            //  alignment).
            masterSalt.CopyTo(iv);

            // XOR keyId (56-bit) into iv using big-endian segments
            var hiSpan = iv.Slice(7, 4);
            var hi = BinaryPrimitives.ReadUInt32BigEndian(hiSpan);
            hi ^= (uint)(keyId >> 24);
            BinaryPrimitives.WriteUInt32BigEndian(hiSpan, hi);

            var midSpan = iv.Slice(11, 2);
            var mid = BinaryPrimitives.ReadUInt16BigEndian(midSpan);
            mid ^= (ushort)((keyId >> 8) & 0xFFFF);
            BinaryPrimitives.WriteUInt16BigEndian(midSpan, mid);

            iv[13] ^= (byte)keyId;

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

        public static void GenerateMessageKeyIV(Span<byte> iv, ReadOnlySpan<byte> salt, uint ssrc, ulong index)
        {
            if (iv.Length != BLOCK_SIZE)
            {
                Throw.ArgumentException($"IV buffer must be exactly {BLOCK_SIZE} bytes", nameof(iv));
            }

            // RFC 3711 - 4.1.1
            // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
            salt.Slice(0, 14).CopyTo(iv);

            // XOR SSRC big-endian
            var ssrcSpan = iv.Slice(4, 4);
            var ssrcVal = BinaryPrimitives.ReadUInt32BigEndian(ssrcSpan);
            ssrcVal ^= ssrc;
            BinaryPrimitives.WriteUInt32BigEndian(ssrcSpan, ssrcVal);

            // XOR index big-endian (48-bit)
            var hiSpan2 = iv.Slice(8, 4);
            var hi2 = BinaryPrimitives.ReadUInt32BigEndian(hiSpan2);
            hi2 ^= (uint)(index >> 16);
            BinaryPrimitives.WriteUInt32BigEndian(hiSpan2, hi2);

            var loSpan2 = iv.Slice(12, 2);
            var lo2 = BinaryPrimitives.ReadUInt16BigEndian(loSpan2);
            lo2 ^= (ushort)(index & 0xFFFF);
            BinaryPrimitives.WriteUInt16BigEndian(loSpan2, lo2);

            iv[14] = 0;
            iv[15] = 0;
        }

        public static void Encrypt(Span<byte> output, IBlockCipher engine, ReadOnlySpan<byte> payload, Span<byte> iv)
        {
            if (output.Length < payload.Length)
            {
                Throw.ArgumentException("Output buffer must be at least as large as payload", nameof(output));
            }

            var payloadSize = payload.Length;
            var bufferSize = ((payloadSize + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
            var buffer = ArrayPool<byte>.Shared.Rent(bufferSize + iv.Length);
            var cipher = buffer.AsSpan(0, bufferSize);
            var ivWork = buffer.AsSpan(bufferSize, iv.Length);

            try
            {
                iv.CopyTo(ivWork);

                var blocks = (payloadSize + BLOCK_SIZE - 1) / BLOCK_SIZE;
                for (int blockIdx = 0, start = 0; blockIdx < blocks; blockIdx++, start += BLOCK_SIZE)
                {
                    ivWork[14] = (byte)((blockIdx >> 8) & 0xff);
                    ivWork[15] = (byte)(blockIdx & 0xff);
#if NET8_0_OR_GREATER
                    engine.ProcessBlock(input: ivWork, output: cipher.Slice(start, BLOCK_SIZE));
#else
                    engine.ProcessBlock(inBuf: buffer, inOff: bufferSize, outBuf: buffer, outOff: start);
#endif
                }

                int i = 0;
#if NET8_0_OR_GREATER
                if (Vector.IsHardwareAccelerated)
                {
                    int vecSize = Vector<byte>.Count;

                    for (; i <= payloadSize - vecSize; i += vecSize)
                    {
                        var vPayload = new Vector<byte>(payload.Slice(i, vecSize));
                        var vCipher = new Vector<byte>(cipher.Slice(i, vecSize));
                        (vPayload ^ vCipher).CopyTo(output.Slice(i, vecSize));
                    }
                }
#endif

                for (; i < payloadSize; i++)
                {
                    output[i] = (byte)(payload[i] ^ cipher[i]);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }
}
