using System;
using System.Linq;

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

            var generator = new SharpSRTP.SRTP.SrtpKeyGenerator(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
            byte[] iv = generator.GenerateIV(masterSaltBytes, 0, 0, (byte)label);
            string initializationVector = Convert.ToHexString(iv);

            iv[14] = (byte)((counter >> 8) & 0xff);
            iv[15] = (byte)(counter & 0xff);

            byte[] ck = generator.GenerateCipherKey(masterKeyBytes, masterSaltBytes, iv);
            if (label == 2 || label == 5) // 2 is for salt
                ck = ck.Take(14).ToArray();

            string cipherKey = Convert.ToHexString(ck);
            Assert.AreEqual(expectedResult, cipherKey);
        }
    }
}
