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

namespace SharpSRTP.Tests
{
    /// <summary>
    /// The ArraySegment and byte[] overloads netstandard2.0 has are there on net8.0 and later too, so
    /// a library built against the netstandard2.0 SharpSRTP runs on either. They are the same calls on
    /// both frameworks here: the original ones on net481, the ones that hand over to the Span
    /// overloads on net10.0.
    /// </summary>
    [TestClass]
    public class TestFrameworkOverloads
    {
        private const string MasterKeySalt = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";
        private const string Rtp = "80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0";
        private const string Srtp = "80e1000103cb6bc84218a6a3cf77c0bc864411afc82ac978b1087b699bf51892b46152bcf95963dbc69f7efbb776c79a0daa3e2e7ae8a3ceda005fb29b068d099d0b0a103ae0bc9ae62b55c0c8dca25583478377f2bb310f0371a2ada32a119e96a84c796b9376a093409e21a7b16bafedbc4fffadabe5f770e895ec36b8de959819aac706aba8788ba9da2fd3f58bd43796fd51124e92117d98575cc82d302741a8be3c9234bafeb42d2c52ebd9e6edfcb1e7e01fb40131758c9d1181525b1c02e35cc34b46e0aaf1df4dc931036aaf4f9044b47058d22008395596e8000b4a7def6aa97a989e76f0c88ba939313459373a6f";

        private static SrtpSessionContext CreateContext()
        {
            var keys = SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, Convert.FromBase64String(MasterKeySalt));
            return SrtpProtocol.CreateSrtpSessionContext(keys);
        }

        private static void AssertProtectsAndUnprotects(ISrtpContext sender, ISrtpContext receiver)
        {
            byte[] rtp = Convert.FromHexString(Rtp);

            byte[] protectedPacket = new byte[sender.CalculateRequiredSrtpPayloadLength(rtp.Length)];
            Assert.AreEqual(0, sender.ProtectRtp(new ArraySegment<byte>(rtp), protectedPacket, out int protectedLength));
            CollectionAssert.AreEqual(Convert.FromHexString(Srtp), protectedPacket.AsSpan(0, protectedLength).ToArray());

            byte[] unprotected = new byte[protectedLength];
            Assert.AreEqual(0, receiver.UnprotectRtp(new ArraySegment<byte>(protectedPacket, 0, protectedLength), unprotected, out int unprotectedLength));
            CollectionAssert.AreEqual(rtp, unprotected.AsSpan(0, unprotectedLength).ToArray());
        }

        [TestMethod]
        public void SessionContextTakesArraySegmentAndArray()
        {
            AssertProtectsAndUnprotects(CreateContext(), CreateContext());
        }

        [TestMethod]
        public void ThreadSafeSessionContextTakesArraySegmentAndArray()
        {
            AssertProtectsAndUnprotects(new ThreadSafeSrtpSessionContext(CreateContext()), new ThreadSafeSrtpSessionContext(CreateContext()));
        }

        [TestMethod]
        public void ClassOverloadsTakeArraySegmentAndArray()
        {
            // called on the class rather than the interface, as code built against netstandard2.0 does
            SrtpSessionContext sender = CreateContext();
            byte[] rtp = Convert.FromHexString(Rtp);
            byte[] protectedPacket = new byte[sender.CalculateRequiredSrtpPayloadLength(rtp.Length)];

            Assert.AreEqual(0, sender.ProtectRtp(new ArraySegment<byte>(rtp), protectedPacket, out int protectedLength));

            CollectionAssert.AreEqual(Convert.FromHexString(Srtp), protectedPacket.AsSpan(0, protectedLength).ToArray());
        }

        [TestMethod]
        public void RtcpRoundTripsThroughArraySegmentAndArray()
        {
            byte[] rtcp =
            {
                0x80, 0xC8, 0x00, 0x06,
                0xCA, 0xFE, 0xBA, 0xBE,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01
            };
            SrtpSessionContext sender = CreateContext();
            SrtpSessionContext receiver = CreateContext();

            byte[] protectedPacket = new byte[sender.CalculateRequiredSrtcpPayloadLength(rtcp.Length)];
            Assert.AreEqual(0, sender.ProtectRtcp(new ArraySegment<byte>(rtcp), protectedPacket, out int protectedLength));

            byte[] unprotected = new byte[protectedLength];
            Assert.AreEqual(0, receiver.UnprotectRtcp(new ArraySegment<byte>(protectedPacket, 0, protectedLength), unprotected, out int unprotectedLength));

            CollectionAssert.AreEqual(rtcp, unprotected.AsSpan(0, unprotectedLength).ToArray());
        }

        [TestMethod]
        public void AMissingOutputIsRefused()
        {
            SrtpSessionContext context = CreateContext();
            var input = new ArraySegment<byte>(Convert.FromHexString(Rtp));

            Assert.ThrowsExactly<ArgumentNullException>(() => context.ProtectRtp(input, null, out _));
            Assert.ThrowsExactly<ArgumentNullException>(() => context.ProtectRtcp(input, null, out _));
        }

#if NET8_0_OR_GREATER
        [TestMethod]
        public void AnImplementationOfOnlyTheSpanMembersIsReachedThroughTheArrayOnes()
        {
            // the interface's own overloads hand over to the Span members a class implements
            ISrtpContext context = new SpanOnlyContext(CreateContext());

            AssertProtectsAndUnprotects(context, new SpanOnlyContext(CreateContext()));
        }

        private sealed class SpanOnlyContext : ISrtpContext
        {
            private readonly ISrtpContext _inner;

            public SpanOnlyContext(ISrtpContext inner) => _inner = inner;

            public int CalculateRequiredSrtpPayloadLength(int rtpLen) => _inner.CalculateRequiredSrtpPayloadLength(rtpLen);
            public int CalculateRequiredSrtcpPayloadLength(int rtpLen) => _inner.CalculateRequiredSrtcpPayloadLength(rtpLen);
            public int ProtectRtp(ReadOnlySpan<byte> input, Span<byte> output, out int outputBufferLength) => _inner.ProtectRtp(input, output, out outputBufferLength);
            public int UnprotectRtp(ReadOnlySpan<byte> input, Span<byte> output, out int outputBufferLength) => _inner.UnprotectRtp(input, output, out outputBufferLength);
            public int ProtectRtcp(ReadOnlySpan<byte> input, Span<byte> output, out int outputBufferLength) => _inner.ProtectRtcp(input, output, out outputBufferLength);
            public int UnprotectRtcp(ReadOnlySpan<byte> input, Span<byte> output, out int outputBufferLength) => _inner.UnprotectRtcp(input, output, out outputBufferLength);
        }
#endif
    }
}
