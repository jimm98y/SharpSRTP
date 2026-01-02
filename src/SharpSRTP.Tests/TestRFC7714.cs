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

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using SharpSRTP.SRTP.Encryption;
using SharpSRTP.SRTP.Readers;
using System;
using System.Linq;

namespace Srtp.Tests
{
    /// <summary>
    /// RFC 7714 tests. https://www.rfc-editor.org/rfc/rfc7714
    /// </summary>
    [TestClass]
    public sealed class TestRFC7714
    {
        [DataRow("8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "517569642070726f2071756f", "51753c6580c2726f20718414")]
        [TestMethod]
        public void Test_IV_RTP(string rtp, string sk_s, string expectedIv)
        {
            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_s = Convert.FromHexString(sk_s);

            uint ssrc = RtpReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytes);
            ulong index = SrtpContext.GenerateRtpIndex(0, sequenceNumber);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            string ivString = Convert.ToHexString(iv).ToLowerInvariant();
            Assert.AreEqual(expectedIv, ivString);
        }

        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce")]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13")]
        [TestMethod]
        public void Test_Encrypt_RTP(int dtlsProtectionProfile, string rtp, string sk_e, string sk_s, string expectedSrtp)
        {
            SrtpProtectionProfileConfiguration protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[dtlsProtectionProfile];

            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_e = Convert.FromHexString(sk_e);
            byte[] k_s = Convert.FromHexString(sk_s);

            uint ssrc = RtpReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytes);
            ulong index = SrtpContext.GenerateRtpIndex(0, sequenceNumber);
            int n_tag = protectionProfile.AuthTagLength >> 3;
            int offset = RtpReader.ReadHeaderLen(rtpBytes);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = result.Take(offset).ToArray();
            AEAD.Encrypt(cipher, result, offset, rtpBytes.Length, iv, k_e, n_tag, associatedData);

            string encryptedRTP = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(expectedSrtp, encryptedRTP);
        }

        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573")]
        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573")]
        [TestMethod]
        public void Test_Decrypt_RTP(int dtlsProtectionProfile, string srtp, string sk_e, string sk_s, string expectedRtp)
        {
            SrtpProtectionProfileConfiguration protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[dtlsProtectionProfile];

            byte[] srtpBytes = Convert.FromHexString(srtp);
            byte[] k_e = Convert.FromHexString(sk_e);
            byte[] k_s = Convert.FromHexString(sk_s);

            uint ssrc = RtpReader.ReadSsrc(srtpBytes);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(srtpBytes);
            ulong index = SrtpContext.GenerateRtpIndex(0, sequenceNumber);
            int n_tag = protectionProfile.AuthTagLength >> 3;
            int offset = RtpReader.ReadHeaderLen(srtpBytes);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = srtpBytes.Take(offset).ToArray();
            AEAD.Encrypt(cipher, srtpBytes, offset, srtpBytes.Length - n_tag, iv, k_e, n_tag, associatedData);

            string result = Convert.ToHexString(srtpBytes.Take(srtpBytes.Length - n_tag).ToArray()).ToLowerInvariant();
            Assert.AreEqual(expectedRtp, result);
        }

        [DataRow("81c8000e4d6172734e5450314e545031525450200000042a0000eb984c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "517569642070726f2071756f", (uint)0x000005d4, "517524055203726f207170bb")]
        [TestMethod]
        public void Test_IV_RTCP(string rtcp, string sk_s, uint index, string expectedIv)
        {
            byte[] rtpBytes = Convert.FromHexString(rtcp);
            byte[] k_s = Convert.FromHexString(sk_s);
            uint ssrc = RtcpReader.ReadSsrc(rtpBytes);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);
            string ivString = Convert.ToHexString(iv).ToLowerInvariant();
            Assert.AreEqual(expectedIv, ivString);
        }

        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", (uint)0x000005d4, "81c8000d4d61727363e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade800005d4")]
        [TestMethod]
        public void Test_Encrypt_RTCP(int dtlsProtectionProfile, string rtcp, string sk_e, string sk_s, uint idx, string expectedSrtcp)
        {
            SrtpProtectionProfileConfiguration protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[dtlsProtectionProfile];

            byte[] rtcpBytes = Convert.FromHexString(rtcp);
            byte[] k_e = Convert.FromHexString(sk_e);
            byte[] k_s = Convert.FromHexString(sk_s);
            uint ssrc = RtcpReader.ReadSsrc(rtcpBytes);

            int offset = RtcpReader.GetHeaderLen();
            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, idx);

            int n_tag = protectionProfile.AuthTagLength >> 3;
            byte[] srtcp = new byte[rtcpBytes.Length + n_tag + 4];
            Buffer.BlockCopy(rtcpBytes, 0, srtcp, 0, rtcpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            const uint E_FLAG = 0x80000000;
            uint index = idx | E_FLAG;
            byte[] associatedData = srtcp.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
            AEAD.Encrypt(cipher, srtcp, offset, rtcpBytes.Length, iv, k_e, n_tag, associatedData);

            srtcp[rtcpBytes.Length + n_tag + 0] = (byte)(index >> 24);
            srtcp[rtcpBytes.Length + n_tag + 1] = (byte)(index >> 16);
            srtcp[rtcpBytes.Length + n_tag + 2] = (byte)(index >> 8);
            srtcp[rtcpBytes.Length + n_tag + 3] = (byte)index;

            string result = Convert.ToHexString(srtcp).ToLowerInvariant();
            Assert.AreEqual(expectedSrtcp, result);
        }

        [DataRow(ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, "81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c282c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de0476f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")]
        [TestMethod]
        public void Test_Decrypt_RTCP(int dtlsProtectionProfile, string srtcp, string sk_e, string sk_s, string expectedRtcp)
        {
            SrtpProtectionProfileConfiguration protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[dtlsProtectionProfile];

            byte[] srtcpBytes = Convert.FromHexString(srtcp);
            byte[] k_e = Convert.FromHexString(sk_e);
            byte[] k_s = Convert.FromHexString(sk_s);

            int n_tag = protectionProfile.AuthTagLength >> 3;
            uint ssrc = RtcpReader.ReadSsrc(srtcpBytes);
            uint idx = RtcpReader.SrtcpReadIndex(srtcpBytes, 0);
            
            const uint E_FLAG = 0x80000000;
            uint index = idx & ~E_FLAG;
            int offset = RtcpReader.GetHeaderLen();

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = srtcpBytes.Take(offset).Concat(srtcpBytes.Skip(srtcpBytes.Length - 4).Take(4)).ToArray(); // associatedData include also index
            AEAD.Encrypt(cipher, srtcpBytes, offset, srtcpBytes.Length - 4 - n_tag, iv, k_e, n_tag, associatedData);

            string result = Convert.ToHexString(srtcpBytes.Take(srtcpBytes.Length - 4 - n_tag).ToArray()).ToLowerInvariant();
            Assert.AreEqual(expectedRtcp, result);
        }
    }
}
