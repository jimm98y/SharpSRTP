﻿using SharpSRTP.SRTP;
using System;
using System.Buffers.Binary;

namespace SharpSRTP.Tests
{
    /// <summary>SRTCP of the E flag clear, of an AEAD profile, is refused: of no HMAC, nothing would authenticate it.</summary>
    [TestClass]
    public class TestUnencryptedSrtcp
    {
        private static SrtpSessionContext Context(string suite) => SrtpProtocol.CreateSrtpSessionContext(SrtpProtocol.CreateMasterKeys(suite));

        // a sender report, a tag of garbage and the E flag clear, as forged of no key (RFC 7714 9.1)
        private static byte[] Forged(uint ssrc, uint index)
        {
            byte[] packet = new byte[28 + 16 + 4];
            packet[0] = 0x80;
            packet[1] = 200;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 6);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), ssrc);
            packet.AsSpan(28, 16).Fill(0xAA);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(44), index & 0x7FFFFFFF);
            return packet;
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.AEAD_AES_128_GCM)]
        [DataRow(SrtpCryptoSuites.AEAD_AES_256_GCM)]
        public void RefusesAnUnencryptedSrtcp(string suite)
        {
            var context = Context(suite);
            byte[] forged = Forged(0x12345678, 0x7FFFFFFF);
            Assert.AreEqual(SrtpContext.ERROR_HMAC_CHECK_FAILED, context.UnprotectRtcp(forged, forged.Length, out _));
            Assert.AreEqual(0, context.DecodeRtcpContext.ReplayProtection.Count);

            // the replay window as it was: an authentic packet of the source after the forged one of the highest index, taken
            byte[] packet = new byte[28 + 16 + 4];
            Forged(0x12345678, 0).AsSpan(0, 28).CopyTo(packet);
            Assert.AreEqual(0, context.ProtectRtcp(packet, 28, out int length));
            Assert.AreEqual(0, context.UnprotectRtcp(packet, length, out int unprotected));
            Assert.AreEqual(28, unprotected);
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.AEAD_AES_128_GCM)]
        [DataRow(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80)]
        public void CountsNoForgedPacketOfTheMasterKey(string suite)
        {
            var context = Context(suite);
            byte[] rtp = new byte[12 + 16 + 10];
            rtp[0] = 0x80;
            byte[] rtcp = Forged(0x12345678, 0x80000001);
            for (int i = 0; i < 10; i++)
            {
                Assert.AreNotEqual(0, context.UnprotectRtp(rtp, rtp.Length, out _));
                Assert.AreNotEqual(0, context.UnprotectRtcp(rtcp, rtcp.Length, out _));
            }
            Assert.AreEqual(0, context.DecodeRtpContext.MasterKeySentCounter);
            Assert.AreEqual(0, context.DecodeRtcpContext.MasterKeySentCounter);
        }

        [TestMethod]
        public void NumbersSrtcpPast65535()
        {
            var context = Context(SrtpCryptoSuites.AEAD_AES_128_GCM);
            byte[] packet = new byte[28 + 16 + 4];
            uint index = 0;
            for (int i = 0; i <= 65536; i++)
            {
                Forged(0x12345678, 0).AsSpan(0, 28).CopyTo(packet);
                Assert.AreEqual(0, context.ProtectRtcp(packet, 28, out int length));
                index = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(length - 4)) & 0x7FFFFFFF;
            }
            Assert.AreEqual(65536u, index, "of its 31 bits (RFC 3711 3.4), not of 16: of a wrap, its IV again");
        }

        [TestMethod]
        public void RefusesAnSrtpOfAHeaderPastItsEndOfNoException()
        {
            var context = Context(SrtpCryptoSuites.AEAD_AES_128_GCM);
            byte[] packet = new byte[12 + 16];
            packet[0] = 0x8F; // 15 CSRCs
            Assert.AreEqual(SrtpContext.ERROR_GENERIC, context.UnprotectRtp(packet, packet.Length, out _));
            packet[0] = 0x90; // an extension of 65535 words
            packet[14] = packet[15] = 0xFF;
            Assert.AreEqual(SrtpContext.ERROR_GENERIC, context.UnprotectRtp(packet, packet.Length, out _));
            Assert.AreEqual(SrtpContext.ERROR_GENERIC, context.UnprotectRtp(packet, 11, out _));
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.AEAD_AES_128_GCM)]
        [DataRow(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80)]
        public void RefusesAnSrtcpTooShortOfNoException(string suite)
        {
            var context = Context(suite);
            var random = new Random(3);
            for (int length = 0; length < 28; length++)
            {
                byte[] packet = new byte[Math.Max(length, 1)];
                random.NextBytes(packet);
                packet[0] = 0x80;
                Assert.AreNotEqual(0, context.UnprotectRtcp(packet, length, out _), $"of {length} bytes");
            }
        }

#if NET
        [TestMethod]
        public void TheAesGcmOfTheSessionKeyIsReplacedOfTheNextAndDisposed()
        {
            var context = Context(SrtpCryptoSuites.AEAD_AES_128_GCM).EncodeRtpContext;
            var first = context._payloadAesGcm;
            Assert.IsNotNull(first);

            context.DeriveSessionKeys(1);
            Assert.AreNotSame(first, context._payloadAesGcm);
            Assert.ThrowsExactly<ObjectDisposedException>(() => first.Encrypt(new byte[12], new byte[0], new byte[0], new byte[16]));

            context.Dispose();
            Assert.IsNull(context._payloadAesGcm);
        }

        [TestMethod]
        public void TheThreadSafeWrapperDisposesTheContextItWraps()
        {
            var session = Context(SrtpCryptoSuites.AEAD_AES_128_GCM);
            new ThreadSafeSrtpSessionContext(session).Dispose();
            Assert.IsNull(session.EncodeRtpContext._payloadAesGcm);
        }
#endif
    }
}
