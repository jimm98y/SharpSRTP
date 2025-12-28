using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using SharpSRTP.SRTP;
using SharpSRTP.SRTP.Encryption;
using System;
using System.Linq;

namespace Srtp.Tests
{
    [TestClass]
    public sealed class TestRFC7714
    {
        // https://datatracker.ietf.org/doc/html/rfc3711#appendix-B.3
        [TestMethod]
        [DataRow("8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "517569642070726f2071756f", "51753c6580c2726f20718414")]
        public void Test_IV_RTP(string rtp, string salt, string expectedIv)
        {
            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_s = Convert.FromHexString(salt);

            uint ssrc = RTPReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(rtpBytes);
            ulong index = SRTProtocol.GenerateRTPIndex(0, sequenceNumber);

            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, index);

            string ivString = Convert.ToHexString(iv).ToLowerInvariant();
            Assert.AreEqual(expectedIv, ivString);
        }

        [TestMethod]
        [DataRow("8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce")]
        [DataRow("8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13")]
        public void Test_Encrypt_RTP(string rtp, string key, string salt, string expectedEncryptedRTP)
        {
            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt);

            uint ssrc = RTPReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(rtpBytes);
            ulong index = SRTProtocol.GenerateRTPIndex(0, sequenceNumber);
            const int n_tag = 16;

            int offset = RTPReader.ReadHeaderLen(rtpBytes);

            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = result.Take(offset).ToArray();
            AESGCM.Encrypt(cipher, result, offset, rtpBytes.Length, iv, k_e, n_tag, associatedData);

            string encryptedRTP = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(expectedEncryptedRTP, encryptedRTP);
        }

        [TestMethod]
        [DataRow("8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573")]
        [DataRow("8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573")]
        public void Test_Decrypt_RTP(string srtp, string key, string salt, string expectedDecryptedRTP)
        {
            byte[] srtpBytes = Convert.FromHexString(srtp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt);

            uint ssrc = RTPReader.ReadSsrc(srtpBytes);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(srtpBytes);
            ulong index = SRTProtocol.GenerateRTPIndex(0, sequenceNumber);
            const int n_tag = 16;

            int offset = RTPReader.ReadHeaderLen(srtpBytes);

            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());
            byte[] associatedData = srtpBytes.Take(offset).ToArray();
            AESGCM.Encrypt(cipher, srtpBytes, offset, srtpBytes.Length - n_tag, iv, k_e, n_tag, associatedData);

            string decryptedRTP = Convert.ToHexString(srtpBytes.Take(srtpBytes.Length - n_tag).ToArray()).ToLowerInvariant();
            Assert.AreEqual(expectedDecryptedRTP, decryptedRTP);
        }

        // https://datatracker.ietf.org/doc/html/rfc3711#appendix-B.3
        [TestMethod]
        [DataRow("81c8000e4d6172734e5450314e545031525450200000042a0000eb984c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "517569642070726f2071756f", (uint)0x000005d4, "517524055203726f207170bb")]
        public void Test_IV_RTCP(string rtcp, string salt, uint index, string expectedIv)
        {
            byte[] rtpBytes = Convert.FromHexString(rtcp);
            byte[] k_s = Convert.FromHexString(salt);

            uint ssrc = RTCPReader.ReadSsrc(rtpBytes);
            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, index);

            string ivString = Convert.ToHexString(iv).ToLowerInvariant();
            Assert.AreEqual(expectedIv, ivString);
        }

        [TestMethod]
        [DataRow("81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "000102030405060708090a0b0c0d0e0f", "517569642070726f2071756f", (uint)0x000005d4, "81c8000d4d61727363e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade800005d4")]
        public void Test_Encrypt_RTCP(string rtcp, string key, string salt, uint idx, string expectedSRTCP)
        {
            byte[] rtcpBytes = Convert.FromHexString(rtcp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt);
            uint ssrc = RTCPReader.ReadSsrc(rtcpBytes);

            int offset = RTCPReader.GetHeaderLen();
            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, idx);

            const int n_tag = 16;
            byte[] result = new byte[rtcpBytes.Length + n_tag + 4];
            Buffer.BlockCopy(rtcpBytes, 0, result, 0, rtcpBytes.Length);

            var cipher = new GcmBlockCipher(new AesEngine());

            const uint E_FLAG = 0x80000000;
            uint index = idx | E_FLAG;
            byte[] associatedData = result.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
            AESGCM.Encrypt(cipher, result, offset, rtcpBytes.Length, iv, k_e, n_tag, associatedData);

            result[rtcpBytes.Length + n_tag + 0] = (byte)(index >> 24);
            result[rtcpBytes.Length + n_tag + 1] = (byte)(index >> 16);
            result[rtcpBytes.Length + n_tag + 2] = (byte)(index >> 8);
            result[rtcpBytes.Length + n_tag + 3] = (byte)index;

            string encryptedRTCP = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(expectedSRTCP, encryptedRTCP);
        }

        [TestMethod]
        [DataRow("81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c282c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de0476f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "517569642070726f2071756f", "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")]
        public void Test_Decrypt_RTCP(string srtcp, string key, string salt, string expectedRTCP)
        {
            byte[] srtcpBytes = Convert.FromHexString(srtcp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt);

            const int n_tag = 16;

            uint ssrc = RTCPReader.ReadSsrc(srtcpBytes);
            uint idx = RTCPReader.SRTCPReadIndex(srtcpBytes, 0);
            
            const uint E_FLAG = 0x80000000;
            uint index = idx & ~E_FLAG;

            int offset = RTCPReader.GetHeaderLen();
            byte[] iv = AESGCM.GenerateMessageKeyIV(k_s, ssrc, index);

            var cipher = new GcmBlockCipher(new AesEngine());

            byte[] associatedData = srtcpBytes.Take(offset).Concat(srtcpBytes.Skip(srtcpBytes.Length - 4).Take(4)).ToArray(); // associatedData include also index
            AESGCM.Encrypt(cipher, srtcpBytes, offset, srtcpBytes.Length - 4 - n_tag, iv, k_e, n_tag, associatedData);

            string decryptedRTCP = Convert.ToHexString(srtcpBytes.Take(srtcpBytes.Length - 4 - n_tag).ToArray()).ToLowerInvariant();
            Assert.AreEqual(expectedRTCP, decryptedRTCP);
        }
    }
}
