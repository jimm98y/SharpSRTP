using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using SharpSRTP.SRTP;
using SharpSRTP.SRTP.Authentication;
using SharpSRTP.SRTP.Encryption;
using System;
using System.Linq;

namespace Srtp.Tests
{
    [TestClass]
    public sealed class TestRFC8269
    {
        // Test vectors constructed from the RFC 8269 by concatenating RTP header + encrypted RTP payload + authentication tag.
        [TestMethod]
        [DataRow("0c5ffd37a11edc42c325287fc0604f2e", "f93563311b354748c97891379553063116452309", "cd3a7c42c671e0067a2a2639b43a", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5eb1bf753f412e6f35058cc398dc851aae3a6ccdcb463fbed9cfb3de2fb76fdffa9e481f5efb64c92487f59dabbc7cc72da092485f3fbad87888820b86037311fa44330e18a59a1e1338ba2c21458493a57463475c54691f91cec785429119e0dfcd9048f90e07fecd50b528e8c62ee6e71445de5d7f659405135aff3604c2ca4ff4aaca40809cb9eee42cc4ad23230757081ca289f2851d3315e9568b501fdce6df9de4e729054672b0e35")]
        [DataRow("0c5ffd37a11edc42c325287fc0604f2e3e8cd5671a00fe3216aa5eb105783b54", "f93563311b354748c97891379553063116452309", "cd3a7c42c671e0067a2a2639b43a", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5ebc424c59fd5696305e5b13d8e8ca7656617ccd7471088af9debf07b55c750f804a5ac2b737be48140958a9b420524112ae72e4da5bca59d2b1019ddd7dbdc30b43d5f046152ced40947d62d2c93e7b8e50f02db2b6b61b010e4c1566884de1fa9702cdf8157e8aedfe3dd77c76bb50c25ae4d624615c15acfdeeb5f79482aaa01d3e4c05eb601eca2bd10518e9d46b02116359232e9eac0fabd05235dd09e6dea192f515fab04bbb4e62c")]
        public void Test_Encrypt_ARIACTR_RTP(string k_e, string k_a, string k_s, string rtp, string srtp)
        {
            byte[] bk_e = Convert.FromHexString(k_e);
            byte[] bk_a = Convert.FromHexString(k_a);
            byte[] bk_s = Convert.FromHexString(k_s);

            byte[] payloadRaw = Convert.FromHexString(rtp);
            int length = payloadRaw.Length;
            byte[] payload = new byte[2048];
            Buffer.BlockCopy(payloadRaw, 0, payload, 0, length);

            uint ssrc = RTPReader.ReadSsrc(payload);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(payload);
            int offset = RTPReader.ReadHeaderLen(payload);

            uint roc = 0;
            ulong index = ((ulong)roc << 16) | sequenceNumber;
            byte[] iv = ARIACTR.GenerateMessageKeyIV(bk_s, ssrc, index);

            var aria = new AriaEngine();
            aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(bk_e));

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(bk_a));

            ARIACTR.Encrypt(aria, payload, offset, length, iv);

            payload[length + 0] = (byte)(roc >> 24);
            payload[length + 1] = (byte)(roc >> 16);
            payload[length + 2] = (byte)(roc >> 8);
            payload[length + 3] = (byte)roc;

            const int n_tag = 10;
            byte[] auth = HMAC.GenerateAuthTag(hmac, payload, 0, length + 4);
            System.Buffer.BlockCopy(auth, 0, payload, length, n_tag); // we don't append ROC in SRTP
            var result = payload.Take(length + n_tag).ToArray();

            string srtpResult = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(srtp, srtpResult);
        }

        [TestMethod]
        [DataRow("e91e5e75da65554a48181f3846349562", "000000000000000000000000", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5eb4d8a9a0675550c704b17d8c9ddc81a5cd6f7da34f2fe1b3db7cb3dfb9697102ea0f3c1fc2dbc873d44bceeae8e4442974ba21ff6789d3272613fb9631a7cf3f14bacbeb421633a90ffbe58c2fa6bdca534f10d0de0502ce1d531b6336e58878278531e5c22bc6c85bbd784d78d9e680aa19031aaf89101d669d7a3965c1f7e16229d7463e0535f4e253f5d18187d40b8ae0f564bd970b5e7e2adfb211e89a9535abace3f37f5a736f4be984bbffbedc1")]
        [DataRow("0c5ffd37a11edc42c325287fc0604f2e3e8cd5671a00fe3216aa5eb105783b54", "000000000000000000000000", "8008315ebf2e6fe020e8f5ebf57af5fd4ae19562976ec57a5a7ad55a5af5c5e5c5fdf5c55ad57a4a7272d57262e9729566ed66e97ac54a4a5a7ad5e15ae5fdd5fd5ac5d56ae56ad5c572d54ae54ac55a956afd6aed5a4ac562957a9516991691d572fd14e97ae962ed7a9f4a955af572e162f57a956666e17ae1f54a95f566d54a66e16e4afd6a9f7ae1c5c55ae5d56afde916c5e94a6ec56695e14afde1148416e94ad57ac5146ed59d1cc5", "8008315ebf2e6fe020e8f5eb6f9e4bcbc8c85fc0128fb1e4a0a20cb9932ff74581f54fc013dd054b19f99371425b352d97d3f337b90b63d1b082adeeea9d2d7391897d591b985e55fb50cb5350cf7d38dc27dda127c078a149c8eb98083d66363a46e3726af217d3a00275ad5bf772c7610ea4c23006878f0ee69a8397703169a419303f40b72e4573714d19e2697df61e7c7252e5abc6bade876ac4961bfac4d5e867afca351a48aed52822e210d6ced2cf430ff841472915e7ef48")]
        public void Test_Encrypt_ARIAGCM_RTP(string k_e, string k_s, string rtp, string srtp)
        {
            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] bk_e = Convert.FromHexString(k_e);
            byte[] bk_s = Convert.FromHexString(k_s);

            uint ssrc = RTPReader.ReadSsrc(rtpBytes);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(rtpBytes);
            ulong index = SRTProtocol.GenerateRTPIndex(0, sequenceNumber);
            const int n_tag = 16;

            int offset = RTPReader.ReadHeaderLen(rtpBytes);
            byte[] iv = ARIAGCM.GenerateMessageKeyIV(bk_s, ssrc, index);

            byte[] result = new byte[rtpBytes.Length + n_tag];
            Buffer.BlockCopy(rtpBytes, 0, result, 0, rtpBytes.Length);

            var cipher = new GcmBlockCipher(new AriaEngine());
            byte[] associatedData = result.Take(offset).ToArray();
            ARIAGCM.Encrypt(cipher, result, offset, rtpBytes.Length, iv, bk_e, n_tag, associatedData);

            string srtpResult = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(srtp, srtpResult);
        }

        [TestMethod]
        [DataRow(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80, "e1f97a0d3e018be0d64fa32c06de4139", "0ec675ad498afeebb6960b3aabe6", "dbd85a3c4d9219b3e81f7d942e299de4", "d021877bd3eaf92d581ed70ddc050e03f1125703", "9700657f5f34161830d7d85f5dc8", true)]
        [DataRow(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80, "0c5ffd37a11edc42c325287fc0604f2e3e8cd5671a00fe3216aa5eb105783b54", "0ec675ad498afeebb6960b3aabe6", "0649a09d93755fe9c2b2efba1cce930af2e76ce8b77e4b175950321aa94b0cf4", "e58d42915873b71899234807334658f20bc46018", "194abaa8553a8eba8a413a340fc8", true)]
        public void Test_Session_Keys_ARIACTR(int profile, string masterKey, string masterSalt, string k_e, string k_a, string k_s, bool isRtp)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);

            var context = new SRTPContext(profile, masterKeyBytes, masterSaltBytes, isRtp ? SRTPContextType.RTP : SRTPContextType.RTCP);

            string sgk_e = Convert.ToHexString(context.K_e).ToLowerInvariant();
            string sgk_a = Convert.ToHexString(context.K_a).ToLowerInvariant();
            string sgk_s = Convert.ToHexString(context.K_s).ToLowerInvariant();

            Assert.AreEqual(k_e, sgk_e);
            Assert.AreEqual(k_a, sgk_a); // TODO: RFC shows 96 bytes auth key, not sure why
            Assert.AreEqual(k_s, sgk_s);
        }
    }
}
