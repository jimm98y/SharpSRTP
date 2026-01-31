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
using System.Buffers.Binary;

namespace SharpSRTP.Tests
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

            Span<byte> iv = stackalloc byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, index);

            var expectedIvBytes = Convert.FromHexString(expectedIv);
            Assert.IsTrue(iv.SequenceEqual(expectedIvBytes),
                $"IV mismatch.\nExpected: {BitConverter.ToString(expectedIvBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(iv.ToArray()).Replace("-", "").ToLowerInvariant()}");
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

            var iv = new byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = new byte[offset];
            Buffer.BlockCopy(result, 0, associatedData, 0, offset);

            // Encrypt payload -> payload+tag slice
            var payloadSpan = result.AsSpan(offset, rtpBytes.Length - offset);
            var outputSpan = result.AsSpan(offset, (rtpBytes.Length - offset) + n_tag);
            AEAD.Encrypt(outputSpan, cipher, true, payloadSpan, iv, k_e, n_tag, associatedData);

            var expectedSrtpBytes = Convert.FromHexString(expectedSrtp);
            Assert.IsTrue(result.AsSpan().SequenceEqual(expectedSrtpBytes),
                $"SRTP RTP mismatch.\nExpected: {BitConverter.ToString(expectedSrtpBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(result).Replace("-", "").ToLowerInvariant()}");
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

            var iv = new byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = new byte[offset];
            Buffer.BlockCopy(srtpBytes, 0, associatedData, 0, offset);

            // Decrypt payload+tag -> payload slice
            var encSpan = srtpBytes.AsSpan(offset, srtpBytes.Length - offset);
            var outSpan = srtpBytes.AsSpan(offset, srtpBytes.Length - offset);
            AEAD.Encrypt(outSpan, cipher, false, encSpan, iv, k_e, n_tag, associatedData);

            var expectedRtpBytes = Convert.FromHexString(expectedRtp);
            var actualRtpSpan = srtpBytes.AsSpan(0, srtpBytes.Length - n_tag);
            Assert.IsTrue(actualRtpSpan.SequenceEqual(expectedRtpBytes),
                $"SRTP Decrypt RTP mismatch.\nExpected: {BitConverter.ToString(expectedRtpBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(actualRtpSpan.ToArray()).Replace("-", "").ToLowerInvariant()}");
        }

        [DataRow("81c8000e4d6172734e5450314e545031525450200000042a0000eb984c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "517569642070726f2071756f", (uint)0x000005d4, "517524055203726f207170bb")]
        [TestMethod]
        public void Test_IV_RTCP(string rtcp, string sk_s, uint index, string expectedIv)
        {
            byte[] rtpBytes = Convert.FromHexString(rtcp);
            byte[] k_s = Convert.FromHexString(sk_s);
            uint ssrc = RtcpReader.ReadSsrc(rtpBytes);

            Span<byte> iv = stackalloc byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, index);
            var expectedIvBytes = Convert.FromHexString(expectedIv);
            Assert.IsTrue(iv.SequenceEqual(expectedIvBytes),
                $"IV RTCP mismatch.\nExpected: {BitConverter.ToString(expectedIvBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(iv.ToArray()).Replace("-", "").ToLowerInvariant()}");
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
            var iv = new byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, idx);

            int n_tag = protectionProfile.AuthTagLength >> 3;
            byte[] srtcp = new byte[rtcpBytes.Length + n_tag + 4];
            Buffer.BlockCopy(rtcpBytes, 0, srtcp, 0, rtcpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            uint index = idx | SrtpContext.E_FLAG;

            // associatedData include also index
            byte[] associatedData = new byte[offset + 4];
            Array.Copy(srtcp, 0, associatedData, 0, offset);
            BinaryPrimitives.WriteUInt32BigEndian(associatedData.AsSpan(offset, 4), index);

            var payloadSpan = srtcp.AsSpan(offset, rtcpBytes.Length - offset);
            var outputSpan = srtcp.AsSpan(offset, rtcpBytes.Length - offset + n_tag);
            AEAD.Encrypt(outputSpan, cipher, true, payloadSpan, iv, k_e, n_tag, associatedData);

            BinaryPrimitives.WriteUInt32BigEndian(srtcp.AsSpan(rtcpBytes.Length + n_tag, 4), index);

            var expectedSrtcpBytes = Convert.FromHexString(expectedSrtcp);
            Assert.IsTrue(srtcp.AsSpan().SequenceEqual(expectedSrtcpBytes),
                $"SRTP RTCP mismatch.\nExpected: {BitConverter.ToString(expectedSrtcpBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(srtcp).Replace("-", "").ToLowerInvariant()}");
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

            uint index = idx & ~SrtpContext.E_FLAG;
            int offset = RtcpReader.GetHeaderLen();

            var iv = new byte[AEAD.BLOCK_SIZE];
            AEAD.GenerateMessageKeyIV(iv, k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = new byte[offset + 4];
            Array.Copy(srtcpBytes, 0, associatedData, 0, offset);
            BinaryPrimitives.WriteUInt32BigEndian(associatedData.AsSpan(offset, 4),
                BinaryPrimitives.ReadUInt32BigEndian(srtcpBytes.AsSpan(srtcpBytes.Length - 4, 4)));

            var encSpan = srtcpBytes.AsSpan(offset, srtcpBytes.Length - offset - 4);
            var outSpan = srtcpBytes.AsSpan(offset, srtcpBytes.Length - offset);
            AEAD.Encrypt(outSpan, cipher, false, encSpan, iv, k_e, n_tag, associatedData);

            var expectedRtcpBytes = Convert.FromHexString(expectedRtcp);
            var actualRtcpSpan = srtcpBytes.AsSpan(0, srtcpBytes.Length - 4 - n_tag);
            Assert.IsTrue(actualRtcpSpan.SequenceEqual(expectedRtcpBytes),
                $"SRTP Decrypt RTCP mismatch.\nExpected: {BitConverter.ToString(expectedRtcpBytes).Replace("-", "").ToLowerInvariant()}\nActual:   {BitConverter.ToString(actualRtcpSpan.ToArray()).Replace("-", "").ToLowerInvariant()}");
        }
    }
}
