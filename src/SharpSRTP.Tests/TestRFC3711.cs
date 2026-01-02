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
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using SharpSRTP.SRTP.Authentication;
using SharpSRTP.SRTP.Encryption;
using SharpSRTP.SRTP.Readers;
using System;
using System.Linq;

namespace Srtp.Tests
{
    /// <summary>
    /// RFC 3711 tests. https://datatracker.ietf.org/doc/html/rfc3711
    /// </summary>
    [TestClass]
    public sealed class TestRFC3711
    {       
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "E03EAD0935C95E80E166B16DD92B4EB4", 0)]
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "D23513162B02D0F72A43A2FE4A5F97AB", 1)]
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "41E95B3BB0A2E8DD477901E4FCA894C0", 2)]
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "EC8CDF7398607CB0F2D21675EA9EA1E4", 0xFEFF)]
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "362B7C3C6773516318A077D7FC5073AE", 0xFF00)]
        [DataRow("2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000", "6A2CC3787889374FBEB4C81B17BA6C44", 0xFF01)]
        [TestMethod]
        public void Test_Encrypt_AESCM(string kk_e, string sk_s, string keystream, int i)
        {
            byte[] k_e = Convert.FromHexString(kk_e);
            byte[] k_s = Convert.FromHexString(sk_s);
            int roc = 0;
            uint sequenceNumber = 0;
            uint ssrc = 0;

            ulong index = ((ulong)roc << 16) | sequenceNumber;

            AesEngine aes = new AesEngine();
            byte[] iv = CTR.GenerateMessageKeyIV(k_s, ssrc, index);
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(k_e));

            byte[] cipher = new byte[k_s.Length];

            iv[14] = (byte)((i >> 8) & 0xff);
            iv[15] = (byte)(i & 0xff);
            aes.ProcessBlock(iv, 0, cipher, 0);

            string payloadString = Convert.ToHexString(cipher);
            Assert.AreEqual(keystream, payloadString);
        }

        [DataRow("72db0646db1e98b02a0056ef700c6cb2", "45111565691aa9d235afee475b12", "57dca73c834ac313d7fdbe58f4df5d93", "a0482b8914db8219f0ec4e54c2f32c4f854eeacf", "8666bc4b1ec16deb3e28fed64da3", true, false)]
        [DataRow("bf75d35600e7ebf8e32abbc946095224", "c573d00b2acbfd25292b1a5ce3fb", "530e566d05b76f7f14b557a27651a47a", "baac16ae6c3215c44089029e229e3507c25377c9", "97090496db451c9464dce1d0ce03", true, false)]
        [DataRow("e2d05f16f1128c2dbe5aa1138f312670", "1938ad696ebe161712592d9ec63a", "2d4f0386508113f7cf8d2267fe765d5c", "19b01657c4d9e88267f251f1939ed4bbb4f2ee8c", "9f36b51b79f849e18c3abb3cae82", true, false)]
        [TestMethod]
        public void Test_Session_Keys_AESCM(string masterKey, string masterSalt, string k_e, string k_a, string k_s, bool isRtp, bool isClient)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);

            var protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80];
            var context = new SrtpContext(protectionProfile, null, masterKeyBytes, masterSaltBytes, isRtp ? SrtpContextType.RTP : SrtpContextType.RTCP);

            string sgk_e = Convert.ToHexString(context.K_e).ToLowerInvariant();
            string sgk_a = Convert.ToHexString(context.K_a).ToLowerInvariant();
            string sgk_s = Convert.ToHexString(context.K_s).ToLowerInvariant();

            Assert.AreEqual(k_e, sgk_e);
            Assert.AreEqual(k_a, sgk_a);
            Assert.AreEqual(k_s, sgk_s);
        }

        [DataRow("503073e919570c4be07872a22f6f682e", "f635137879c3dbf0d3b422aee13b", "45bd0c56f87f8013721257c9322c1fbf", "fc958d05c608be655f16c1f2b423223de9a9cdc2", "c5029308e55be19e3911ce68a1af", true, "8061eb7f8b1f6f186dc9803d67640028acb402802dc8", "8061eb7f8b1f6f186dc9803df7be778106050cb06813102c2ff82d9f51f2c52c")]
        [DataRow("503073e919570c4be07872a22f6f682e", "f635137879c3dbf0d3b422aee13b", "45bd0c56f87f8013721257c9322c1fbf", "fc958d05c608be655f16c1f2b423223de9a9cdc2", "c5029308e55be19e3911ce68a1af", true, "8061eb808b1f6f186dc9803d68ee019e2c00", "8061eb808b1f6f186dc9803dbdf1992f8e54519542e68c831e6b8649")]
        [DataRow("503073e919570c4be07872a22f6f682e", "f635137879c3dbf0d3b422aee13b", "45bd0c56f87f8013721257c9322c1fbf", "fc958d05c608be655f16c1f2b423223de9a9cdc2", "c5029308e55be19e3911ce68a1af", true, "8061eb818b1f6f186dc9803d67640028acb402802dc8", "8061eb818b1f6f186dc9803dcf37424ff6966861a616f9fe3bea89d3c51bc1f6")]
        [DataRow("503073e919570c4be07872a22f6f682e", "f635137879c3dbf0d3b422aee13b", "45bd0c56f87f8013721257c9322c1fbf", "fc958d05c608be655f16c1f2b423223de9a9cdc2", "c5029308e55be19e3911ce68a1af", true, "8061eb828b1f6f186dc9803d68ee019e2c00", "8061eb828b1f6f186dc9803daa953548e0aa7f28a722ea4591f8fdf4")]
        [DataRow("503073e919570c4be07872a22f6f682e", "f635137879c3dbf0d3b422aee13b", "45bd0c56f87f8013721257c9322c1fbf", "fc958d05c608be655f16c1f2b423223de9a9cdc2", "c5029308e55be19e3911ce68a1af", true, "8061eb838b1f6f186dc9803d7c85b84071c36053668080df72fe7ecb35fad2a5a4ceab4b17b3c30c78ce55161454e922cd45fc6c2b6ed1066985239ad067dfdef0735f67527f28346f2d72cd6896c2fb5163f3364a6a56595519845c5feebed7dfe69cea5d5065c072c08e2a0f81392a0531f0f412589b7cef18ff80030781425c94d82722887222b635eef9d0487269e9472ba1cef2e34b874c859aaac78ac4d1fd33bc6c4c1fe93c74b0c8d6f096d2030e12d198c7e1aee29aaf45976b144a6395b09988e7c5d15da68a46f8bdea806e4b365041e756a30c4a7322431acaecfc56ec051a2676a55b8d2f587307072435528c2a8d63836849af9ffafb8a46cd5955f74cc1fde53cc6afa00186bf10e05be8e9693b0a91d7f2993974fa44558b0671bba0824ec87b58d4bcae6bf27cf2017a9abc45111f4f0249e221697e0abe59b96b349a4ee3d65754da35c16c64507ca708ded491b9ccfea90bf8c2a991b2c281acd6015df9137b0bd0270184a85633e6760eaa6ea9dd909ca886b486f54b4371fdbdba493665f7a3915f807ed20366511fa2cabd3f7e93536227e3d8518ebe7523257bfd09eca8d81c4e52b91a18b26d2642ae035ca7718e9ca34d54bdaeffadf84afb5c4f9906c181cf080bdeb49069b486286d53040cea45b7edb8d8fa6f327214c2a3fb22ebd89e1b43ddf90e5c3c659d48eb64b524c1612c21a0702dee014c99d487563c7cd764fbc098fb32c28ed0448ab24e260b42e6d47ca7205303aeca04fd144a33c01099cd22197aa51487cc10eedc48aeb24e32bd1014e26915c94804c1ef9fff38509858a6128d9a084fd86afa71caf5fa9ccf594993803dca25a1cee54c3ab2ee6ebcb475cceaa23c3fe9e44db05d4d88e7f6899705c5df2187ec8c0da9ab239c12b5f8777c66a15a7a4403db8811e889884ab58ea29b52fdd1c380e9b715feba226e02aaf6b30e5ed8ef4fec5a680a239106d091d77aefc64b3ee125c93f4934846d0a024cfe73ebb96a028b74ee56ca1df1951f0d3b25f4fc8e31e59bbce237db858c93623b5df9eb216d3433b8b9858720f3cbf3386163a25cf385577d7b0ace67fd40fbd5dcc37d5e86c376ab1d259b23e4ad522f2d81241e42cb967488e10d36faab6c2876cfcd7da303623fa0676ba43c48195aa294f4fb273ad5219a6aeb4c4aa8d9e241c9e462f34b509894ef8eaeed8f688072dde31e2e5659c6db4522b3d15acb18013a8667bff310ed4b48b3f81dd7d94504e4ec7111fce6d0b461ba26b836f5604c90ddf395cf48c45f47e6559bbd6d0c4d3f96b8ae7c0455cabe5b890b195efe0aaf20faba918d90e4095a34f72be38829a2fde66d7b6d5ed4ee42a77793e0e0a7a86af5f426fbc29e47cc5202da33ce94bc26012b33bf2dfb8a9a9a928eb02896bea380b03534dac834677ebf703cdf8ce3532c57727974e9b70bad5024474e2a2f799ea8ab05e99e2c20474a5f453fe7aaaba0a56c0d7ad15f3dec71986d3200d1cfc910c575711f06fb00c3e4cd4c34d3920b42373d59fde5b5cf9f30e467df9abcf8be0ed2bba6ac3e81e5f7bc8cabd3b26a36b8f936432cc72bc9459d7aa8d26e62acdad4a8aa5dcb4165466f83a440ecc8abd2bd34fef783372d02c89cdddecc0eeba89b17596578bd709840ee78fc0150f5d7523300e8de6d56d749d26ae81402e2ae614f7720c0faed45409cc0d41d3951b8e13735e146ad96f4383e8868d8b6ed5ebba07f5bfc476e073fec323c3e64483c93314011b55b4d5e788922355deff86120b900a375f07247c26cbe969aa75e341777f22551c740606f4f1f974b61f9cdaf6dc52d9e897ab7c3e3b6a5d22bec3a34cdc268b18a38a9bdd8cb116331e35d3bdd0d763286cb59c9777fc5ef089d9ec4e7b29d5a39351c4995218ce3dcf35a1772963bfb18d7", "8061eb838b1f6f186dc9803d9907f21219810a0f68d5fc96247e0e3d50117729a0cd93edafa0ec87a6bef9e1232dc4d4a408a1769f648a875c44d60486b96fb8a385242dcff40e47fd6993b55cebf27ca9476aa8ed0f8bae4a8a30630a72e5b55421b143af2a7460b40cb1451ce07ae1dc67ff35ed1d9b16d36ae861b778069a5c76a77f9224ddc06128d334853af0654553358f0d9f9ff93b0a0bf342a8cfc189ea9c5e58695219ea7b79549f1cde516c031ca151d3631c5786e4edacfe17c4357a61de444bd503b82f11d3f862c1049ff34d607ca6f221a0d748cdb02cfda8492afd871de4129ac508683dc062e20673f3b25d8ba6eb9c982dc83be65ee5ffac461f78c55574163aac4c1fbcc508fe249efd67ddf10fba916cd35f8cac5e9c0b8a8a89ce785bc6d4b349ef53ab36e703bebb00b1ab35caee2c6caf3b946c49acba0e4a161878ad01d2a24b28a68c31cd97ef1544cf2d9dd705726a6c0b300a274d87de710ce7fc982382fd80716fce8a9ad6a7dc7f911d32e2b282c44262fb0f4a1e209d70b8830f841db883011a9b62dd2ac8cd5c0cb57a1d513c279f351504c4ac37b916d755efed179797485f78e64bc45f3605d2c780b481793514c46cc25e09732a1a5173cad900071973e16fcc7df0c9dfc3bd8c5524ace2c78fecdfd89e25e0598dde23e15ae0a4923ac621647eefca93c768670ca2f88f5080db5b2627c2b41b45d7a5024ba393c08e08e5799c75568fb2c8739a47a873a623cdb6a723d65816b41d7a856bc747f80eb5fd0c71787b1dfce49bf50a5ea74e5d8b6d81b6200723ba3d7c9418898ff55fad0e63c5d522d4300ac9362e1cdd63cc6c43825a70d9887a93c5dc8678aa0fc764c1b30c476b94c6aed5b106ab0e70f87ec6d9f4d23a782f38583287180aa16e941b48532db7cde3f127ad1ae0d5edd8295300989c56decdb8709488a7ef2f742fcb4d05f6d0ee40b0447dcc186d31e1b1436c56ec9629c8f4ac798aaf739cf64ea70805d66d9a28d4e267b90be5857ab26790648e1d84e6a813cc6ab6200e42099ec0b4beb46e4a5dddb2295caa2cbc52565b532b0b374e12a9aff0935e768929d354a6509bf3da7347e75711c66489958b85f420861c4ace5c08cf935ca4580a2d4e031e8725b63bd08d8dba3d8023bbbb83cb91ed6fdf9bbaf6fa4b7850ffea6673f5eecc605a73a6e4befbdb11a9f24655d6fe4f6d6f47dfd005c90ed296509d994d222b345cf30d1a919e6c5deabc99d3ed91bc043d2a1aa1da38dfcbe7dbdb02ded89fc0780b609c0824d982fed0b2e8019a46d206af36da3f0493c903b7498d504dfc2c85e8b20923d24dd4b3bf88058902e440fe9dbe8513396ca0ae50c358f2bd9a773dfdf177208e9b3949f100f736662f2b90eb9e43e6cce891d8e8b3257ef25535a115cd7cff2189defdac37e615f0de6500cef61658f99c3d94880f9658c6372cc813bbd5eca8abb275b519a1b79048abb7dd8841a2da98d79b1b761969d034f2ece5d8b08fe3eae943bcd44bb3f76ab18790dd9ada447817adf6149605848d998da8922b178755aa6d54d3cc05916bcec66244327646a9a792ada1b76eac5ec1d5a1cf6db2ab5dbd5b9bb2d7049067215a5b107eb01128ceed808f1c5bd578da0f4dc5fb976a83d3a20b5b9a1f5e106430f6b50935bb132d72ccfa36425cef4504973856e59e96e360180339251a7ac8be8385d7bc8a67cfafc4127616ddd0d79379ffbf80efe9e6599599f516f59c15ff47ef38b71fecead08f9cc22c1a77dc7784a4360a0b94e594ba970a4f31f61467df7c7b04b58c95bf9177b8973bfb396a0f463982e1457218a87d7848a43bc6c846393375030d1da8d606a53a05459e86b9f50bfdd6f79aa89e4343c610103ad49e08df25f75e9ffcd3c6a18d0334a533defac7d087f984d7e61ac7355fb61975")]
        [TestMethod]
        public void Test_Session_Keys_AESCM_RTP(string masterKey, string masterSalt, string k_e, string k_a, string k_s, bool isRtp, string rtp, string srtp)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);

            var protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80];
            var context = new SrtpContext(protectionProfile, null, masterKeyBytes, masterSaltBytes, isRtp ? SrtpContextType.RTP : SrtpContextType.RTCP);

            string sgk_e = Convert.ToHexString(context.K_e);
            string sgk_a = Convert.ToHexString(context.K_a);
            string sgk_s = Convert.ToHexString(context.K_s);

            Assert.AreEqual(k_e.ToUpperInvariant(), sgk_e);
            Assert.AreEqual(k_a.ToUpperInvariant(), sgk_a);
            Assert.AreEqual(k_s.ToUpperInvariant(), sgk_s);

            byte[] payloadRaw = Convert.FromHexString(rtp);
            int length = payloadRaw.Length;
            byte[] payload = new byte[2048];
            Buffer.BlockCopy(payloadRaw, 0, payload, 0, length);

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);
            int offset = RtpReader.ReadHeaderLen(payload);

            uint roc = 0;
            ulong index = ((ulong)roc << 16) | sequenceNumber;
            byte[] iv = CTR.GenerateMessageKeyIV(context.K_s, ssrc, index);

            var aes = new AesEngine();
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(context.K_e));

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(context.K_a));

            CTR.Encrypt(aes, payload, offset, length, iv);

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

        [DataRow("7c70686d319cdb521a6b71d883f9ce08", "68d48dc36f7f29c860eae2e3be5b", "36db45fe23d42378ffc1df8f8241f26b", "a5a171c0a334826513056abe124e22417fa21a86", "fad326f5f9a17147157f82602566", false, false, 0u, "80c8000667160dd7ecf549a36fdf3b6499f322dc00000083000288e781ca000267160dd701000000", "80c8000667160dd794c8324dbed8d36fe8e0b6afa47cc7e05f436ec763e8a1e9081aefa22e084c1d800000002af3b0da27475b47bee1")]
        [DataRow("7c70686d319cdb521a6b71d883f9ce08", "68d48dc36f7f29c860eae2e3be5b", "36db45fe23d42378ffc1df8f8241f26b", "a5a171c0a334826513056abe124e22417fa21a86", "fad326f5f9a17147157f82602566", false, false, 1u, "80c8000667160dd7ecf549a470624dd299f48320000000c20003a98b81ca000267160dd701000000", "80c8000667160dd7c7708f404d42f4f1cae25b397578f88986d19eea6cb8b8bcf3e45330fb4e0ceb800000015f3f9dbe4f835ab1291d")]
        [DataRow("7c70686d319cdb521a6b71d883f9ce08", "68d48dc36f7f29c860eae2e3be5b", "36db45fe23d42378ffc1df8f8241f26b", "a5a171c0a334826513056abe124e22417fa21a86", "fad326f5f9a17147157f82602566", false, false, 2u, "80c8000667160dd7ecf549a57020c49b99f5e256000001340005d83b81ca000267160dd701000000", "80c8000667160dd7b42f73c3adb3dbff1f9644cd89f8a2305b1bbc641c5a6d704fea376d697b7cd2800000029c0c2e3b7775633ae4d1")]
        [TestMethod]
        public void Test_Session_Keys_AESCM_RTCP(string masterKey, string masterSalt, string k_e, string k_a, string k_s, bool isRtp, bool isClient, uint S_l, string rtcp, string srtcp)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);

            var protectionProfile = DtlsSrtpProtocol.DtlsProtectionProfiles[ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80];
            var context = new SrtpContext(protectionProfile, null, masterKeyBytes, masterSaltBytes, SrtpContextType.RTCP);

            string sgk_e = Convert.ToHexString(context.K_e);
            string sgk_a = Convert.ToHexString(context.K_a);
            string sgk_s = Convert.ToHexString(context.K_s);

            Assert.AreEqual(k_e.ToUpperInvariant(), sgk_e);
            Assert.AreEqual(k_a.ToUpperInvariant(), sgk_a);
            Assert.AreEqual(k_s.ToUpperInvariant(), sgk_s);

            byte[] payloadRaw = Convert.FromHexString(rtcp);
            int length = payloadRaw.Length;
            byte[] payload = new byte[2048];
            Buffer.BlockCopy(payloadRaw, 0, payload, 0, length);

            uint ssrc = RtcpReader.ReadSsrc(payload);
            const uint E_FLAG = 0x80000000;
            uint index = S_l | E_FLAG;

            int offset = RtcpReader.GetHeaderLen();
            byte[] iv = CTR.GenerateMessageKeyIV(context.K_s, ssrc, S_l);

            var aes = new AesEngine();
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(context.K_e));

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(context.K_a));

            CTR.Encrypt(aes, payload, offset, length, iv);

            payload[length + 0] = (byte)(index >> 24);
            payload[length + 1] = (byte)(index >> 16);
            payload[length + 2] = (byte)(index >> 8);
            payload[length + 3] = (byte)index;

            const int n_tag = 10;
            byte[] auth = HMAC.GenerateAuthTag(hmac, payload, 0, length + 4);
            System.Buffer.BlockCopy(auth, 0, payload, length + 4, n_tag); // we don't append ROC in SRTP
            var result = payload.Take(length + 4 + n_tag).ToArray();

            string srtpResult = Convert.ToHexString(result).ToLowerInvariant();
            Assert.AreEqual(srtcp, srtpResult);
        }

        [DataRow("806e5cba50681de55c62159970736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67", 0xd462564a, "234829008467be186c3de14aae72d62c", "32f2870d", "806e5cba50681de55c621599019ce7a26e7854014a6366aa95d4eefd1ad4172a14f9faf455b7f1d4b62bd08f562c0eef7c4802")]
        [TestMethod]
        public void Test_AESF8(string rtp, uint roc, string k_e, string k_s, string expectedSrtp)
        {
            byte[] bk_e = Convert.FromHexString(k_e);
            byte[] bk_s = Convert.FromHexString(k_s);
            byte[] rtpBytes = Convert.FromHexString(rtp);

            uint sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytes);
            uint ssrc = RtpReader.ReadSsrc(rtpBytes);
            int offset = RtpReader.ReadHeaderLen(rtpBytes);
            ulong index = ((ulong)roc << 16) | sequenceNumber;

            AesEngine aes = new AesEngine();
            byte[] iv = F8.GenerateRtpMessageKeyIV(aes, bk_e, bk_s, rtpBytes, roc);

            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(bk_e));
            F8.Encrypt(aes, rtpBytes, offset, rtpBytes.Length, iv);

            string payloadString = Convert.ToHexString(rtpBytes).ToLowerInvariant();
            Assert.AreEqual(expectedSrtp, payloadString);
        }
    }
}
