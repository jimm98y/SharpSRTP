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

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers;
using System.Buffers.Binary;

#if NET8_0_OR_GREATER
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
using Bytes = System.Span<byte>;
#else
using ReadOnlyBytes = byte[];
using Bytes = byte[];
#endif

namespace SharpSRTP.SRTP.Encryption
{
    public static class AEAD
    {
        public const int BLOCK_SIZE = 12;

        public static void Encrypt(Span<byte> output, IAeadBlockCipher engine, bool encrypt, ReadOnlySpan<byte> payload, byte[] iv, ReadOnlyMemory<byte> K_e, int N_tag, byte[] associatedData)
        {
            var payloadSize = payload.Length;
            var expectedLength = engine.GetOutputSize(payloadSize);

            Throw.IfLessThan(output.Length, expectedLength);

            var parameters = new AeadParameters(K_e.ToKeyParameter(), N_tag << 3, iv, associatedData);
            engine.Init(encrypt, parameters);

#if NET8_0_OR_GREATER
            var len = engine.ProcessBytes(payload, output);

            // throws when the MAC fails to match
            len += engine.DoFinal(output.Slice(len));
#else
            var bytes = ArrayPool<byte>.Shared.Rent(Math.Max(payloadSize, output.Length));
            try
            {
                payload.CopyTo(bytes);

                var len = engine.ProcessBytes(bytes, 0, payloadSize, bytes, 0);

                // throws when the MAC fails to match
                len += engine.DoFinal(bytes, len);

                // Copy result to output span
                bytes.AsSpan(0, len).CopyTo(output);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes);
            }
#endif
        }

        public static void GenerateMessageKeyIV(Span<byte> iv, ReadOnlySpan<byte> k_s, uint ssrc, ulong index)
        {
            if (iv.Length != BLOCK_SIZE)
            {
                Throw.ArgumentException($"IV Bytes must be exactly {BLOCK_SIZE} bytes", nameof(iv));
            }

            k_s.Slice(0, 12).CopyTo(iv);

            // XOR in SSRC (big-endian)
            var ssrcSpan = iv.Slice(2, 4);
            var ssrcVal = BinaryPrimitives.ReadUInt32BigEndian(ssrcSpan);
            ssrcVal ^= ssrc;
            BinaryPrimitives.WriteUInt32BigEndian(ssrcSpan, ssrcVal);

            // XOR in index high 48bits using big-endian 32-bit and 16-bit segments
            var hiSpan = iv.Slice(6, 4);
            var hi = BinaryPrimitives.ReadUInt32BigEndian(hiSpan);
            hi ^= (uint)(index >> 16);
            BinaryPrimitives.WriteUInt32BigEndian(hiSpan, hi);

            var loSpan = iv.Slice(10, 2);
            var lo = BinaryPrimitives.ReadUInt16BigEndian(loSpan);
            lo ^= (ushort)(index & 0xFFFF);
            BinaryPrimitives.WriteUInt16BigEndian(loSpan, lo);
        }
    }
}
