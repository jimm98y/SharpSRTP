// SharpSRTP
// Copyright (C) 2026 Lukas Volf
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
using System.Linq;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// A stream whose first RTP sequence number is 0 - a sender's first is random, and 0 is one of them - unprotected by a
    /// receiver of a context of its own: its first packet, the next, and a replay of the first refused.
    /// </summary>
    [TestClass]
    public class TestSequenceZero
    {
        private const string MasterKeySalt = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";

        private static byte[] Rtp(ushort sequenceNumber)
        {
            byte[] packet = new byte[12 + 20];
            packet[0] = 0x80;
            packet[1] = 96;
            packet[2] = (byte)(sequenceNumber >> 8);
            packet[3] = (byte)sequenceNumber;
            packet[8] = 0x11; packet[9] = 0x22; packet[10] = 0x33; packet[11] = 0x44;
            for (int i = 12; i < packet.Length; i++)
                packet[i] = (byte)i;
            return packet;
        }

        private static byte[] Protect(SrtpSessionContext sender, byte[] rtp)
        {
            byte[] buffer = new byte[sender.CalculateRequiredSrtpPayloadLength(rtp.Length)];
            rtp.CopyTo(buffer, 0);
            Assert.AreEqual(0, sender.ProtectRtp(buffer, rtp.Length, out int length));
            return buffer.Take(length).ToArray();
        }

        private static int Unprotect(SrtpSessionContext receiver, byte[] srtp, out byte[] rtp)
        {
            byte[] buffer = (byte[])srtp.Clone();
            int result = receiver.UnprotectRtp(buffer, buffer.Length, out int length);
            rtp = buffer.Take(length).ToArray();
            return result;
        }

        private static (SrtpSessionContext Sender, SrtpSessionContext Receiver) Contexts(string suite)
        {
            // of each suite its own length of master key and salt: AES-128's 16 and 14, AES-256-GCM's 32 and 12
            byte[] masterKeySalt = suite == SrtpCryptoSuites.AEAD_AES_256_GCM
                ? Enumerable.Range(1, 44).Select(i => (byte)i).ToArray()
                : Convert.FromBase64String(MasterKeySalt);
            return (SrtpProtocol.CreateSrtpSessionContext(SrtpProtocol.CreateMasterKeys(suite, null, masterKeySalt)),
                SrtpProtocol.CreateSrtpSessionContext(SrtpProtocol.CreateMasterKeys(suite, null, masterKeySalt)));
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80)]
        [DataRow(SrtpCryptoSuites.AEAD_AES_256_GCM)]
        public void UnprotectsAStreamStartingAtSequenceZero(string suite)
        {
            var (sender, receiver) = Contexts(suite);
            byte[] first = Protect(sender, Rtp(0));
            byte[] second = Protect(sender, Rtp(1));

            Assert.AreEqual(0, Unprotect(receiver, first, out byte[] rtp), "the first packet, of sequence number 0");
            CollectionAssert.AreEqual(Rtp(0), rtp);
            Assert.AreEqual(0, Unprotect(receiver, second, out rtp), "the next");
            CollectionAssert.AreEqual(Rtp(1), rtp);
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80)]
        [DataRow(SrtpCryptoSuites.AEAD_AES_256_GCM)]
        public void RefusesAReplayOfSequenceZero(string suite)
        {
            var (sender, receiver) = Contexts(suite);
            byte[] first = Protect(sender, Rtp(0));

            Assert.AreEqual(0, Unprotect(receiver, first, out _));
            Assert.AreEqual(SrtpContext.ERROR_REPLAY_CHECK_FAILED, Unprotect(receiver, first, out _), "packet 0 again is a replay");
        }

        [TestMethod]
        public void UnprotectsTheFirstSrtcpIndex()
        {
            // an SRTCP stream's first index is 0 (RFC 3711 3.3.1)
            var (sender, receiver) = Contexts(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80);
            byte[] report = { 0x80, 201, 0, 1, 0x11, 0x22, 0x33, 0x44 };
            byte[] buffer = new byte[sender.CalculateRequiredSrtcpPayloadLength(report.Length)];
            report.CopyTo(buffer, 0);
            Assert.AreEqual(0, sender.ProtectRtcp(buffer, report.Length, out int length));

            byte[] srtcp = buffer.Take(length).ToArray();
            Assert.AreEqual(0, receiver.UnprotectRtcp(srtcp, srtcp.Length, out int unprotected));
            CollectionAssert.AreEqual(report, srtcp.Take(unprotected).ToArray());
            Assert.AreEqual(SrtpContext.ERROR_REPLAY_CHECK_FAILED, receiver.UnprotectRtcp(buffer.Take(length).ToArray(), length, out _), "index 0 again is a replay");
        }
    }
}
