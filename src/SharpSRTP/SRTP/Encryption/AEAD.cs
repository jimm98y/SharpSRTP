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
using System.Buffers.Binary;

namespace SharpSRTP.SRTP.Encryption
{
    public static class AEAD
    {
        public static void Encrypt(IAeadBlockCipher engine, bool encrypt, byte[] payload, int offset, int length, byte[] iv, byte[] K_e, int N_tag, byte[] associatedData)
        {
            Encrypt(engine, encrypt, payload, offset, length, iv, new KeyParameter(K_e), N_tag, associatedData);
        }

        public static void Encrypt(IAeadBlockCipher engine, bool encrypt, byte[] payload, int offset, int length, byte[] iv, KeyParameter K_e, int N_tag, byte[] associatedData)
        {
            int payloadSize = length - offset;

            var parameters = new AeadParameters(K_e, N_tag << 3, iv, associatedData);
            engine.Init(encrypt, parameters);

            int len = engine.ProcessBytes(payload, offset, payloadSize, payload, offset);

            // throws when the MAC fails to match
            engine.DoFinal(payload, offset + len);
        }

        public static byte[] GenerateMessageKeyIV(ReadOnlySpan<byte> k_s, uint ssrc, ulong index)
        {
            byte[] iv = GC.AllocateUninitializedArray<byte>(12);
            k_s.Slice(0, 12).CopyTo(iv);

            // XOR ssrc at offset 2 (3 bytes for 48-bit index)
            var ssrcSpan = iv.AsSpan(2, 4);
            BinaryPrimitives.WriteUInt32BigEndian(ssrcSpan,
                BinaryPrimitives.ReadUInt32BigEndian(ssrcSpan) ^ ssrc);

            // XOR index at offset 6 (6 bytes for 48-bit index)
            var indexSpan = iv.AsSpan(4, 8);
            BinaryPrimitives.WriteUInt64BigEndian(indexSpan,
                BinaryPrimitives.ReadUInt64BigEndian(indexSpan) ^ (index & 0x0000_FFFF_FFFF_FFFF));

            return iv;
        }

        public static byte[] GenerateMessageKeyIV(ArraySegment<byte> k_s, uint ssrc, ulong index)
        {
            byte[] iv = GC.AllocateUninitializedArray<byte>(12);
            Buffer.BlockCopy(k_s.Array, k_s.Offset, iv, 0, 12);

            // XOR ssrc at offset 2 (3 bytes for 48-bit index)
            var ssrcSpan = iv.AsSpan(2, 4);
            BinaryPrimitives.WriteUInt32BigEndian(ssrcSpan,
                BinaryPrimitives.ReadUInt32BigEndian(ssrcSpan) ^ ssrc);

            // XOR index at offset 6 (6 bytes for 48-bit index)
            var indexSpan = iv.AsSpan(4, 8);
            BinaryPrimitives.WriteUInt64BigEndian(indexSpan,
                BinaryPrimitives.ReadUInt64BigEndian(indexSpan) ^ (index & 0x0000_FFFF_FFFF_FFFF));

            return iv;
        }
    }
}
