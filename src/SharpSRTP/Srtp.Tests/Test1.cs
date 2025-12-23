using Org.BouncyCastle.Crypto.Engines;
using SharpSRTP.SRTP;
using System;

namespace Srtp.Tests
{
    [TestClass]
    public sealed class Test1
    {
        // https://datatracker.ietf.org/doc/html/rfc3711#appendix-B.3
        [TestMethod]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 0, 0, "C61E7A93744F39EE10734AFE3FF7A087")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 2, 0, "30CBBC08863D8C85D49DB34A9AE1")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 0, "CEBE321F6FF7716B6FD4AB49AF256A15")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 1, "6D38BAA48F0A0ACF3C34E2359E6CDBCE")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 2, "E049646C43D9327AD175578EF7227098")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 3, "6371C10C9A369AC2F94A8C5FBCDDDC25")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 4, "6D6E919A48B610EF17C2041E47403576")]
        [DataRow("E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", 1, 5, "6B68642C59BBFC2F34DB60DBDFB2DC68")]
        public void TestCipherSalt(string masterKey, string masterSalt, int label, int counter, string expectedResult)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);

            byte[] ck = SrtpKeyGenerator.GenerateSessionKey(masterKeyBytes, masterSaltBytes, label, counter);

            string cipherKey = Convert.ToHexString(ck);
            Assert.AreEqual(expectedResult, cipherKey);
        }

        [TestMethod]
        [DataRow("E03EAD0935C95E80E166B16DD92B4EB4", 0)]
        [DataRow("D23513162B02D0F72A43A2FE4A5F97AB", 1)]
        [DataRow("41E95B3BB0A2E8DD477901E4FCA894C0", 2)]
        [DataRow("EC8CDF7398607CB0F2D21675EA9EA1E4", 0xFEFF)]
        [DataRow("362B7C3C6773516318A077D7FC5073AE", 0xFF00)]
        [DataRow("6A2CC3787889374FBEB4C81B17BA6C44", 0xFF01)]
        public void TestAESCM(string keystream, int i)
        {
            byte[] sessionKey = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
            int roc = 0;
            uint sequenceNumber = 0;
            uint ssrc = 0;
            byte[] k_s = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");

            ulong index = ((ulong)roc << 16) | sequenceNumber;

            AesEngine aes = new AesEngine();
            byte[] iv = SrtpKeyGenerator.GenerateMessageIV(k_s, ssrc, index);
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(sessionKey));

            byte[] cipher = new byte[k_s.Length];

            const int aesBlockSize = 16;
            iv[14] = (byte)((i >> 8) & 0xff);
            iv[15] = (byte)(i & 0xff);
            aes.ProcessBlock(iv, 0, cipher, 0);

            string payloadString = Convert.ToHexString(cipher);
            Assert.AreEqual(keystream, payloadString);
        }
    }
}
