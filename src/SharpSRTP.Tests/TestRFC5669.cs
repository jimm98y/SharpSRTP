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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using SharpSRTP.SRTP;
using SharpSRTP.SRTP.Authentication;
using SharpSRTP.SRTP.Encryption;
using SharpSRTP.SRTP.Readers;
using System;
using System.Linq;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// RFC5699 https://www.rfc-editor.org/rfc/rfc5669.txt
    /// </summary>
    [TestClass]
    public class TestRFC5669
    {
        // RFC 5669:
        // [DataRow(SrtpCryptoSuites.SEED_CTR_128_HMAC_SHA1_80, "0c5ffd37a11edc42c325287fc0604f2e", "f93563311b354748c978913795530631", "cd3a7c42c671e0067a2a2639b43a", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5ebdf5a89291e7e383e9beff765e691a73749c9e33139ad3001cd8da73ad07f69a2805a70358b5c7c8c60ed359f95cf5e08f713c53ff7b808250d79a19ccb8d10734e3cb72ed1f0a4e85b002b248049ab0763dbe571bec52cf9153fdf2019e421ef779cd6f4bd1c8211da8c272e2fce43934b9eabb87362510f254149f992599036f5e43102327db1ac5e78adc4f66546ed7abfb5a4db320fb7b9c52a61bc554e44a5cdaa4d9edc53763855")]
        // Fixed:
        [DataRow(SrtpCryptoSuites.SEED_CTR_128_HMAC_SHA1_80, "0c5ffd37a11edc42c325287fc0604f2e", "f93563311b354748c978913795530631", "cd3a7c42c671e0067a2a2639b43a", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5ebdf5a89291e7e383e9beff765e691a73749c9e33139ad3001cd8da73ad07f69a2805a70358b5c7c8c60ed359f95cf5e08f713c53ff7b808250d79a19ccb8d10734e3cb72ed1f0a4e85b002b248049ab0763dbe571bec52cf9153fdf2019e421ef779cd6f4bd1c8211da8c272e2fce43934b9eabb87362510f254149f992599036f5e43102327db1ac5e78adc4f66546ed7abfb5a4db320fb7b9c52a61bc554e441d82cc2b73bb1517626c")]
        [TestMethod]
        public void Test_Encrypt_RTP_Seed_CTR(string cryptoSuite, string key, string authKey, string salt, string rtp, string srtp)
        {
            SrtpProtectionProfileConfiguration protectionProfile = SrtpProtocol.SrtpCryptoSuites[cryptoSuite];

            byte[] k_e = Convert.FromHexString(key);
            byte[] k_a = Convert.FromHexString(authKey);
            byte[] k_s = Convert.FromHexString(salt);

            byte[] payloadRaw = Convert.FromHexString(rtp);
            int length = payloadRaw.Length;
            byte[] payload = new byte[2048];
            Buffer.BlockCopy(payloadRaw, 0, payload, 0, length);

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);
            int offset = RtpReader.ReadHeaderLen(payload);

            uint roc = 0;
            ulong index = SrtpContext.GenerateRtpIndex(roc, sequenceNumber);
            byte[] iv = CTR.GenerateMessageKeyIV(k_s, ssrc, index);

            var seed = new SeedEngine();
            seed.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(k_e));

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(k_a));

            CTR.Encrypt(seed, payload, offset, length, iv);

            payload[length + 0] = (byte)(roc >> 24);
            payload[length + 1] = (byte)(roc >> 16);
            payload[length + 2] = (byte)(roc >> 8);
            payload[length + 3] = (byte)roc;

            int n_tag = protectionProfile.AuthTagLength >> 3;

            // It seems RFC 5669 has incorrect auth tag calculated from the original payload.
            // For a5cdaa4d9edc53763855 the following code works:
            /*
            byte[] auth = HMAC.GenerateAuthTag(hmac, payloadRaw, 0, length);
            */
            // However, it makes little sense to do it that way, so it's likely a bug and I've updated the test data with a different authTag produced by the standard algorithm
            byte[] auth = HMAC.GenerateAuthTag(hmac, payload, 0, length + 4); 
            System.Buffer.BlockCopy(auth, 0, payload, length, n_tag); // we don't append ROC in SRTP
            var result = payload.Take(length + n_tag).ToArray();

            string srtpResult = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(srtp, srtpResult);
        }

        [DataRow(SrtpCryptoSuites.SEED_128_GCM_96, "e91e5e75da65554a48181f3846349562", "0000000000000000000000000000", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5eb8a5363682c6b1bbf13c0b09cf747a5512543cb2f129b8bd0e92dfadf735cda8f88c4bbf90288f5e58d20c4f1bb0d58446ea009103ee57ba99cdeabaaa18d4a9a05ddb46e7e5290a5a2284fe50b1f6fe9ad3f1348c354181e85b24f1a552a1193cf0e13eed5ab95ae854fb4f5b0edb2d3ee5eb238c8f4bfb136b2eb6cd78760420680ce1879100014f140a15e07e70133ed9cbb6d57b75d574acb0087eefbac9936cd9ae602be3ee2cd8d5d9d")]
        [TestMethod]
        public void Test_Encrypt_RTP_Seed_GCM(string cryptoSuite, string key, string salt, string rtp, string expectedEncryptedRTP)
        {
            SrtpProtectionProfileConfiguration protectionProfile = SrtpProtocol.SrtpCryptoSuites[cryptoSuite];

            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt); // salt must be zero!!!

            uint ssrc = RtpReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytes);
            ulong index = SrtpContext.GenerateRtpIndex(0, sequenceNumber);
            int n_tag = protectionProfile.AuthTagLength >> 3;

            int offset = RtpReader.ReadHeaderLen(rtpBytes);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new GcmBlockCipher(new SeedEngine());
            byte[] associatedData = result.Take(offset).ToArray();
            AEAD.Encrypt(cipher, true, result, offset, rtpBytes.Length, iv, k_e, n_tag, associatedData);

            string encryptedRTP = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(expectedEncryptedRTP, encryptedRTP);
        }

        [DataRow(SrtpCryptoSuites.SEED_128_CCM_80, "974bee725d44fc3992267b284c3c6750", "0000000000000000000000000000", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5eb486843a881df215a8574650ddabf5dbb2650f06f51252bccaeb4012899d6d71e30c64dad5ead5d8ba65ffe9d79aaf30dc9e6334490c07e7533d704114a9006ecb3b3bff59ecf585485bc0bd286ed434cfd684d19a1ad514ca5f37b71d93288c07cf4d5e9b83db8becc8c692a7279b6a9ac62ba970fc54f46dcc926d434c0b5ad8678fbf0e7a03037924dae342ef64fa65b8eaea260fecb477a57e3919c5dab82b0a8274cf6a8bb6cc466")]
        [TestMethod]
        public void Test_Encrypt_RTP_Seed_CCM(string cryptoSuite, string key, string salt, string rtp, string expectedEncryptedRTP)
        {
            SrtpProtectionProfileConfiguration protectionProfile = SrtpProtocol.SrtpCryptoSuites[cryptoSuite];

            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] k_e = Convert.FromHexString(key);
            byte[] k_s = Convert.FromHexString(salt); // salt must be zero!!!

            uint ssrc = RtpReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytes);
            ulong index = SrtpContext.GenerateRtpIndex(0, sequenceNumber);
            int n_tag = protectionProfile.AuthTagLength >> 3;

            int offset = RtpReader.ReadHeaderLen(rtpBytes);

            byte[] iv = AEAD.GenerateMessageKeyIV(k_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new CcmBlockCipher(new SeedEngine());
            byte[] associatedData = result.Take(offset).ToArray();
            AEAD.Encrypt(cipher, true, result, offset, rtpBytes.Length, iv, k_e, n_tag, associatedData);

            string encryptedRTP = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(expectedEncryptedRTP, encryptedRTP);
        }
    }
}
