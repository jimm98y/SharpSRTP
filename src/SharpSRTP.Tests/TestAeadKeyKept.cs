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

#if NET
        [TestMethod]
        public void OfDoubleAeadEachLayerOfAnAesGcmOfItsOwn()
        {
            var keys = DtlsSrtpProtocol.CreateMasterKeys(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM, null, Enumerable.Range(0, 256).Select(i => (byte)i).ToArray());
            var context = DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys).EncodeRtpContext;
            Assert.IsNotNull(context.PayloadAesGcm);
            Assert.IsNotNull(context.PayloadAesGcmOuter);
            context.Dispose();
            Assert.IsNull(context.PayloadAesGcmOuter);
        }
#endif

        private static void ProtectsEachPacketAsANewContext(Func<SrtpSessionContext> create, SrtpSessionContext decode)
        {
            var context = create();
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
