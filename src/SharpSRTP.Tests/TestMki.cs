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

using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// The Master Key Identifier in every protection profile: after the HMAC-protected portion and before the HMAC tag
    /// (RFC 3711 section 3.1), last for AEAD profiles whose tag is part of the ciphertext (RFC 7714 sections 8.1 and 9.1).
    /// </summary>
    [TestClass]
    public class TestMki
    {
        private static readonly byte[] Mki = { 0xA1, 0xB2, 0xC3, 0xD4 };
        private static readonly byte[] Rtp = Convert.FromHexString("80e1000103cb6bc84218a6a3001006c8");
        private static readonly byte[] Rtcp = { 0x80, 0xC8, 0x00, 0x06, 0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

        public static IEnumerable<object[]> Profiles
        {
            get
            {
                foreach (int profile in DtlsSrtpProtocol.DtlsProtectionProfiles.Keys)
                {
                    yield return new object[] { profile, false };
                    yield return new object[] { profile, true };
                }
            }
        }

        public static string ProfileName(System.Reflection.MethodInfo method, object[] data)
            => $"{method.Name} 0x{(int)data[0]:X4} {DtlsSrtpProtocol.DtlsProtectionProfiles[(int)data[0]].Cipher}{((bool)data[1] ? " with MKI" : "")}";

        private static (SrtpSessionContext Sender, SrtpSessionContext Receiver) Contexts(int profile, bool withMki)
        {
            byte[] sharedSecret = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            var keys = DtlsSrtpProtocol.CreateMasterKeys(profile, withMki ? Mki : null, sharedSecret);
            return (DtlsSrtpProtocol.CreateSrtpServerSessionContext(keys), DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys));
        }

        private static bool IsAead(int profile) => DtlsSrtpProtocol.DtlsProtectionProfiles[profile].Auth == SrtpAuth.NONE;

        private static int HmacTagLength(int profile) => IsAead(profile) ? 0 : DtlsSrtpProtocol.DtlsProtectionProfiles[profile].AuthTagLength >> 3;

        [DynamicData(nameof(Profiles), DynamicDataDisplayName = nameof(ProfileName))]
        [TestMethod]
        public void Srtp_RoundTrips(int profile, bool withMki)
        {
            var (sender, receiver) = Contexts(profile, withMki);
            byte[] buffer = new byte[sender.CalculateRequiredSrtpPayloadLength(Rtp.Length)];
            Rtp.CopyTo(buffer, 0);
            Assert.AreEqual(0, sender.ProtectRtp(buffer, Rtp.Length, out int length));

            byte[] srtp = buffer.Take(length).ToArray();
            if (withMki)
            {
                CollectionAssert.AreEqual(Mki, srtp.Skip(length - HmacTagLength(profile) - Mki.Length).Take(Mki.Length).ToArray(), "MKI position");
            }

            Assert.AreEqual(0, receiver.UnprotectRtp(srtp, srtp.Length, out int unprotected));
            CollectionAssert.AreEqual(Rtp, srtp.Take(unprotected).ToArray());
        }

        [DynamicData(nameof(Profiles), DynamicDataDisplayName = nameof(ProfileName))]
        [TestMethod]
        public void Srtcp_RoundTrips(int profile, bool withMki)
        {
            var (sender, receiver) = Contexts(profile, withMki);
            byte[] buffer = new byte[sender.CalculateRequiredSrtcpPayloadLength(Rtcp.Length)];
            Rtcp.CopyTo(buffer, 0);
            Assert.AreEqual(0, sender.ProtectRtcp(buffer, Rtcp.Length, out int length));

            byte[] srtcp = buffer.Take(length).ToArray();
            if (withMki)
            {
                CollectionAssert.AreEqual(Mki, srtcp.Skip(length - HmacTagLength(profile) - Mki.Length).Take(Mki.Length).ToArray(), "MKI position");
            }

            Assert.AreEqual(0, receiver.UnprotectRtcp(srtcp, srtcp.Length, out int unprotected));
            CollectionAssert.AreEqual(Rtcp, srtcp.Take(unprotected).ToArray());
        }

        [DynamicData(nameof(Profiles), DynamicDataDisplayName = nameof(ProfileName))]
        [TestMethod]
        public void WrongMki_IsRejected(int profile, bool withMki)
        {
            if (!withMki)
            {
                return;
            }

            var (sender, receiver) = Contexts(profile, withMki);
            byte[] buffer = new byte[sender.CalculateRequiredSrtpPayloadLength(Rtp.Length)];
            Rtp.CopyTo(buffer, 0);
            Assert.AreEqual(0, sender.ProtectRtp(buffer, Rtp.Length, out int length));

            byte[] srtp = buffer.Take(length).ToArray();
            srtp[length - HmacTagLength(profile) - 1] ^= 0xFF; // last MKI byte
            Assert.AreEqual(SrtpContext.ERROR_MKI_CHECK_FAILED, receiver.UnprotectRtp(srtp, srtp.Length, out _));
        }
    }
}
