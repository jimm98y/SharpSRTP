using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;
using System.Buffers.Binary;
using System.Linq;

namespace SharpSRTP.Tests
{
    /// <summary>Of each packet after the first, of the key BouncyCastle keeps: as a context new to it protects it.</summary>
    [TestClass]
    public class TestAeadKeyKept
    {
        [TestMethod]
        [DataRow(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM)]
        public void OfADtlsProfile(int profile)
        {
            var keys = DtlsSrtpProtocol.CreateMasterKeys(profile, null, Enumerable.Range(0, 256).Select(i => (byte)i).ToArray());
            ProtectsEachPacketAsANewContext(() => DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys), DtlsSrtpProtocol.CreateSrtpServerSessionContext(keys));
        }

        [TestMethod]
        [DataRow(SrtpCryptoSuites.SEED_128_CCM_80)]
        [DataRow(SrtpCryptoSuites.SEED_128_GCM_96)]
        [DataRow(SrtpCryptoSuites.F8_128_HMAC_SHA1_80)]
        public void OfASuite(string suite)
        {
            var keys = SrtpProtocol.CreateMasterKeys(suite);
            ProtectsEachPacketAsANewContext(() => SrtpProtocol.CreateSrtpSessionContext(keys), SrtpProtocol.CreateSrtpSessionContext(keys));
        }

        [TestMethod]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)]
        public void TheSameIndexProtectedAgainIsRefused(int profile)
        {
            // of GCM, a nonce of two packets tells its key of authentication: of .NET's AesGcm as of BouncyCastle's, refused
            var context = DtlsSrtpProtocol.CreateSrtpClientSessionContext(DtlsSrtpProtocol.CreateMasterKeys(profile, null, Enumerable.Range(0, 256).Select(i => (byte)i).ToArray()));
            byte[] rtp = new byte[100];
            rtp[0] = 0x80;
            Assert.AreEqual(0, context.ProtectRtp(rtp.ToArray(), 32, out _));
            Assert.ThrowsExactly<ArgumentException>(() => context.ProtectRtp(rtp.ToArray(), 32, out _));
        }

        [TestMethod]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM)]
        [DataRow(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)]
        public void OfATagFailedNoPlaintextIsLeft(int profile)
        {
            var keys = DtlsSrtpProtocol.CreateMasterKeys(profile, null, Enumerable.Range(0, 256).Select(i => (byte)i).ToArray());
            var encode = DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys);
            var decode = DtlsSrtpProtocol.CreateSrtpServerSessionContext(keys);

            byte[] rtp = new byte[100];
            rtp[0] = 0x80;
            rtp.AsSpan(12, 20).Fill(7);
            Assert.AreEqual(0, encode.ProtectRtp(rtp, 32, out int length));
            rtp[length - 1] ^= 1;
            byte[] output = new byte[100];
            Assert.AreNotEqual(0, decode.UnprotectRtp(new ArraySegment<byte>(rtp, 0, length), output, out _));
            Assert.IsFalse(output.Contains((byte)7), "RTP");

            byte[] rtcp = new byte[100];
            rtcp[0] = 0x80;
            rtcp[1] = 200;
            rtcp[3] = 6;
            rtcp.AsSpan(8, 20).Fill(7);
            Assert.AreEqual(0, encode.ProtectRtcp(rtcp, 28, out length));
            rtcp[length - 5] ^= 1; // of its tag, before the E flag and index
            output = new byte[100];
            Assert.AreNotEqual(0, decode.UnprotectRtcp(new ArraySegment<byte>(rtcp, 0, length), output, out _));
            Assert.IsFalse(output.Contains((byte)7), "RTCP");
        }

#if NET
        [TestMethod]
        public void OfDoubleAeadEachLayerOfAnAesGcmOfItsOwn()
        {
            var keys = DtlsSrtpProtocol.CreateMasterKeys(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM, null, Enumerable.Range(0, 256).Select(i => (byte)i).ToArray());
            var session = DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys);
            var context = session.EncodeRtpContext;
            Assert.IsNotNull(context.PayloadAesGcm);
            Assert.IsNotNull(context.PayloadAesGcmOuter);
            byte[] rtp = new byte[100];
            rtp[0] = 0x80;
            Assert.AreEqual(0, session.ProtectRtp(rtp.ToArray(), 32, out _));
            session.Dispose();
            Assert.IsNull(context.PayloadAesGcmOuter);

            // of BouncyCastle's then, its keys not taken of .NET's before
            rtp[3] = 1;
            Assert.AreEqual(0, session.ProtectRtp(rtp, 32, out _));
        }
#endif

        private static void ProtectsEachPacketAsANewContext(Func<SrtpSessionContext> create, SrtpSessionContext decode)
        {
            var context = create();

            // of a forged packet first, the key BouncyCastle is given of it kept, of the packets after
            byte[] forged = new byte[100];
            forged[0] = 0x80;
            forged[1] = 96;
            BinaryPrimitives.WriteUInt32BigEndian(forged.AsSpan(8), 0x12345678);
            Assert.AreEqual(0, create().ProtectRtp(forged, 32, out int forgedLength));
            forged[forgedLength - 1] ^= 1;
            Assert.AreNotEqual(0, decode.UnprotectRtp(forged, forgedLength, out _));
            for (int i = 0; i < 3; i++)
            {
                byte[] rtp = new byte[12 + 20];
                rtp[0] = 0x80;
                rtp[1] = 96;
                BinaryPrimitives.WriteUInt16BigEndian(rtp.AsSpan(2), (ushort)i);
                BinaryPrimitives.WriteUInt32BigEndian(rtp.AsSpan(8), 0x12345678);
                rtp.AsSpan(12).Fill((byte)i);
                byte[] kept = new byte[100], fresh = new byte[100];
                rtp.CopyTo(kept, 0);
                rtp.CopyTo(fresh, 0);

                Assert.AreEqual(0, context.ProtectRtp(kept, rtp.Length, out int length));
                Assert.AreEqual(0, create().ProtectRtp(fresh, rtp.Length, out int freshLength));
                CollectionAssert.AreEqual(fresh.Take(freshLength).ToArray(), kept.Take(length).ToArray(), $"packet {i}");
                Assert.AreEqual(0, decode.UnprotectRtp(kept, length, out int unprotected));
                CollectionAssert.AreEqual(rtp, kept.Take(unprotected).ToArray(), $"packet {i}");

                byte[] rtcp = new byte[100];
                rtcp[0] = 0x80;
                rtcp[1] = 200;
                BinaryPrimitives.WriteUInt16BigEndian(rtcp.AsSpan(2), 6);
                BinaryPrimitives.WriteUInt32BigEndian(rtcp.AsSpan(4), 0x12345678);
                Assert.AreEqual(0, context.ProtectRtcp(rtcp, 28, out length));
                Assert.AreEqual(0, decode.UnprotectRtcp(rtcp, length, out unprotected));
                Assert.AreEqual(28, unprotected, $"RTCP {i}");
            }
        }
    }
}
