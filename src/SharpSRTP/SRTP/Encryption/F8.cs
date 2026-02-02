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
#if NET8_0_OR_GREATER
using System.Numerics;
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
using Bytes = System.Span<byte>;
#else
using ReadOnlyBytes = byte[];
using Bytes = byte[];
#endif

namespace SharpSRTP.SRTP.Encryption
{
    public static class F8
    {
        public const int BLOCK_SIZE = 16;

        public static void GenerateRtpMessageKeyIV(Bytes iv, IBlockCipher engine, ReadOnlySpan<byte> k_e, ReadOnlySpan<byte> k_s, ReadOnlySpan<byte> rtpPacket, uint ROC)
        {
            if (iv.Length != BLOCK_SIZE)
            {
                Throw.ArgumentException($"IV buffer must be exactly {BLOCK_SIZE} bytes", nameof(iv));
            }

#if NET8_0_OR_GREATER
            Span<byte> iv1 = stackalloc byte[BLOCK_SIZE];
#else
            var iv1 = GC.AllocateUninitializedArray<byte>(BLOCK_SIZE);
#endif
            GenerateRtpIV(iv1, rtpPacket, ROC);
            GenerateIV2(iv, engine, k_e, k_s, iv1);
        }

        private static void GenerateRtpIV(Span<byte> iv, ReadOnlySpan<byte> rtpPacket, uint ROC)
        {
            iv[0] = 0;

            // M + PT + SEQ + TS + SSRC
            rtpPacket.Slice(1, 11).CopyTo(iv.Slice(1));

            // ROC (big-endian)
            BinaryPrimitives.WriteUInt32BigEndian(iv.Slice(12, 4), ROC);
        }

        public static void GenerateRtcpMessageKeyIV(Bytes iv, IBlockCipher engine, ReadOnlySpan<byte> k_e, ReadOnlySpan<byte> k_s, ReadOnlySpan<byte> rtcpPacket, uint index)
        {
            if (iv.Length != BLOCK_SIZE)
            {
                Throw.ArgumentException($"IV buffer must be exactly {BLOCK_SIZE} bytes", nameof(iv));
            }

#if NET8_0_OR_GREATER
            Span<byte> iv1 = stackalloc byte[BLOCK_SIZE];
#else
            var iv1 = GC.AllocateUninitializedArray<byte>(BLOCK_SIZE);
#endif
            GenerateRtcpIV(iv1, rtcpPacket, index);
            GenerateIV2(iv, engine, k_e, k_s, iv1);
        }

        private static void GenerateRtcpIV(Span<byte> iv, ReadOnlySpan<byte> rtcpPacket, uint index)
        {
            // 0..0
            iv.Slice(0, 4).Clear();

            // E + SRTCP index (big-endian)
            BinaryPrimitives.WriteUInt32BigEndian(iv.Slice(4, 4), index);

            // V + P + RC + PT + L + SSRC
            rtcpPacket.Slice(0, 8).CopyTo(iv.Slice(BLOCK_SIZE - 8, 8));
        }

        private static void GenerateIV2(Bytes iv2, IBlockCipher engine, ReadOnlySpan<byte> k_e, ReadOnlySpan<byte> k_s, ReadOnlyBytes iv)
        {
            // IV' = E(k_e XOR m, IV)
            k_e.CopyTo(iv2);

            // m = k_s || 0x555..5
            for (var i = 0; i < BLOCK_SIZE; i++)
            {
                if (i < k_s.Length)
                {
                    iv2[i] ^= k_s[i];
                }
                else
                {
                    iv2[i] ^= 0x55;
                }
            }

            engine.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(iv2));

#if NET8_0_OR_GREATER
            engine.ProcessBlock(iv, iv2);
#else
            engine.ProcessBlock(iv, 0, iv2, 0);
#endif
        }

        public static void Encrypt(Span<byte> output, IBlockCipher aes, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> iv)
        {
            if (output.Length < payload.Length)
            {
                Throw.ArgumentException("Output buffer must be at least as large as payload", nameof(output));
            }

            var payloadSize = payload.Length;
            var blockCount = payloadSize / BLOCK_SIZE + payloadSize % BLOCK_SIZE;
            var buffer = ArrayPool<byte>.Shared.Rent(blockCount * BLOCK_SIZE + iv.Length);

            try
            {
                var iv2 = buffer.AsSpan(buffer.Length - iv.Length);

                var blockNo = 0;
                for (var j = 0U; j < blockCount; j++)
                {
                    iv.CopyTo(iv2);

                    // IV' xor j (big-endian)
                    var span = iv2.Slice(12, 4);
                    var value = BinaryPrimitives.ReadUInt32BigEndian(span);
                    value ^= j;
                    BinaryPrimitives.WriteUInt32BigEndian(span, value);

                    // IV' xor S(-1) xor j
                    if (blockNo > 0)
                    {
                        var previousBlockIndex = BLOCK_SIZE * (blockNo - 1);
                        for (var k = 0; k < BLOCK_SIZE; k++)
                        {
                            iv2[k] = (byte)(iv2[k] ^ buffer[previousBlockIndex + k]);
                        }
                    }

#if NET8_0_OR_GREATER
                    aes.ProcessBlock(input: iv2, output: buffer.AsSpan(BLOCK_SIZE * blockNo, BLOCK_SIZE));
#else
                    aes.ProcessBlock(inBuf: buffer, inOff: buffer.Length - iv.Length, outBuf: buffer, outOff: BLOCK_SIZE * blockNo);
#endif
                    blockNo++;
                }

                // XOR keystream into output efficiently
                var cipherSpan = new Span<byte>(buffer, 0, payloadSize);

                int i = 0;
#if NET8_0_OR_GREATER
                if (Vector.IsHardwareAccelerated)
                {
                    int vecSize = Vector<byte>.Count;

                    for (; i <= payloadSize - vecSize; i += vecSize)
                    {
                        var vPayload = new Vector<byte>(payload.Slice(i, vecSize));
                        var vCipher = new Vector<byte>(cipherSpan.Slice(i, vecSize));
                        (vPayload ^ vCipher).CopyTo(output.Slice(i, vecSize));
                    }
                }
#endif

                for (; i < payloadSize; i++)
                {
                    output[i] = (byte)(payload[i] ^ cipherSpan[i]);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }
}
