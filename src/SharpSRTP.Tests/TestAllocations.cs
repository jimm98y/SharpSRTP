#if NET
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// The DTLS-SRTP profiles of .NET's AES protect and unprotect RTP and RTCP allocating nothing, once warmed up. ARIA's
    /// are BouncyCastle's, .NET having no ARIA, and allocate (about 1.3 KB a round trip for CTR, 3.9 KB for GCM).
    /// </summary>
    [TestClass]
    public sealed class TestAllocations
    {
        private const int Warmup = 100, Packets = 1000;

        public static IEnumerable<object[]> Profiles => DtlsSrtpProtocol.DtlsProtectionProfiles
            .Where(p => !p.Value.Cipher.ToString().Contains("ARIA")).Select(p => new object[] { p.Key });

        [DynamicData(nameof(Profiles))]
        [TestMethod]
        public void ProtectAndUnprotect_AllocateNothing(int profile)
        {
            var configuration = DtlsSrtpProtocol.DtlsProtectionProfiles[profile];
            byte[] secret = new byte[(2 * (configuration.CipherKeyLength + configuration.CipherSaltLength)) >> 3];
            RandomNumberGenerator.Fill(secret);
            var keys = DtlsSrtpProtocol.CreateMasterKeys(profile, null, secret);
            using var server = DtlsSrtpProtocol.CreateSrtpServerSessionContext(keys);
            using var client = DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys);

            byte[] rtp = Convert.FromHexString("80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0");
            byte[] rtcp = Convert.FromHexString("80c80006deadbeef000000000000000000000000000000000000000000000000".Substring(0, 56));
            byte[] buffer = new byte[2048];

            long Run(int first, int count)
            {
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int i = first; i < first + count; i++)
                {
                    // a new sequence number each time, past the replay check
                    rtp.CopyTo(buffer, 0);
                    BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), (ushort)i);
                    Assert.AreEqual(0, SrtpContextExtensions.ProtectRtp(server, buffer, rtp.Length, out int length));
                    Assert.AreEqual(0, SrtpContextExtensions.UnprotectRtp(client, buffer, length, out _));

                    rtcp.CopyTo(buffer, 0);
                    Assert.AreEqual(0, SrtpContextExtensions.ProtectRtcp(server, buffer, rtcp.Length, out length));
                    Assert.AreEqual(0, SrtpContextExtensions.UnprotectRtcp(client, buffer, length, out _));
                }
                return GC.GetAllocatedBytesForCurrentThread() - before;
            }

            Run(1, Warmup);
            Assert.AreEqual(0L, Run(1 + Warmup, Packets), $"bytes allocated over {Packets} RTP and RTCP round trips");
        }
    }
}
#endif
