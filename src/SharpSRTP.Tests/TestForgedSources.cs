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

using SharpSRTP.SRTP;
using System;
using System.Buffers.Binary;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// Packets that do not authenticate, each of an SSRC of its own: none of them is to be remembered, or forged ones of random
    /// sources would grow the replay table without bound.
    /// </summary>
    [TestClass]
    public class TestForgedSources
    {
        private static SrtpSessionContext Context()
        {
            byte[] masterKeySalt = Convert.FromBase64String("n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi");
            return SrtpProtocol.CreateSrtpSessionContext(SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, masterKeySalt));
        }

        [TestMethod]
        public void ForgedRtpOfRandomSourcesIsNotRemembered()
        {
            var context = Context();
            var random = new Random(1);
            for (int i = 0; i < 100; i++)
            {
                byte[] forged = new byte[12 + 20 + 10];
                random.NextBytes(forged);
                forged[0] = 0x80;
                forged[1] = 96;
                Assert.AreNotEqual(0, context.UnprotectRtp(forged, forged.Length, out _));
            }
            Assert.AreEqual(0, context.DecodeRtpContext.ReplayProtection.Count, "no source of a packet that did not authenticate");

            // a packet that does: its source remembered, of its replay window
            byte[] packet = new byte[12 + 20 + 10];
            packet[0] = 0x80;
            packet[1] = 96;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 1);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), 0x12345678);
            Assert.AreEqual(0, context.ProtectRtp(packet, 12 + 20, out int length));
            Assert.AreEqual(0, context.UnprotectRtp(packet, length, out _));
            Assert.AreEqual(1, context.DecodeRtpContext.ReplayProtection.Count);
        }

        [TestMethod]
        public void ForgedRtcpOfRandomSourcesIsNotRemembered()
        {
            var context = Context();
            var random = new Random(2);
            for (int i = 0; i < 100; i++)
            {
                byte[] forged = new byte[8 + 20 + 4 + 10];
                random.NextBytes(forged);
                forged[0] = 0x80;
                forged[1] = 200;
                Assert.AreNotEqual(0, context.UnprotectRtcp(forged, forged.Length, out _));
            }
            Assert.AreEqual(0, context.DecodeRtcpContext.ReplayProtection.Count, "no source of a packet that did not authenticate");
        }
    }
}
