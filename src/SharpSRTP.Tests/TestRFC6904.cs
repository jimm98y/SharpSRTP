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
using System.Data;
using System.Linq;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// RFC6904 https://datatracker.ietf.org/doc/html/rfc6904
    /// </summary>
    [TestClass]
    public class TestRFC6904
    {
        [DataRow(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, SrtpContextType.RTP, "E1F97A0D3E018BE0D64FA32C06DE4139", "0EC675AD498AFEEBB6960B3AABE6", "549752054D6FB708622C4A2E596A1B93", "AB01818174C40D39A3781F7C2D27", 0xCAFEBABE, 0u, (ushort)0x1234, "17 414273A475262748 22 0000C8 30 8E 46 55996386B395FB 00", "00 FFFFFFFFFFFFFFFF 00 000000 00 FF 00 FFFFFFFFFFFFFF 00", "17588A9270F4E15E1C220000C8309546A994F0BC54789700")]
        [TestMethod]
        public void Test_Extension_Encryption(string cryptoSuite, SrtpContextType strpContextType, string masterKey, string masterSalt, string sk_he, string sk_hs, uint ssrc, uint roc, ushort sequenceNumber, string rtpExtensions, string rtpExtensionsMask, string expectedEncryptedExtensions)
        {
            byte[] masterKeyBytes = Convert.FromHexString(masterKey);
            byte[] masterSaltBytes = Convert.FromHexString(masterSalt);
            byte[] masterKeySalt = masterKeyBytes.Concat(masterSaltBytes).ToArray();
            SrtpKeys keys = SrtpProtocol.CreateMasterKeys(cryptoSuite, null, masterKeySalt);
            SrtpSessionContext context = SrtpProtocol.CreateSrtpSessionContext(keys);

            Assert.AreEqual(sk_he, Convert.ToHexString(context.EncodeRtpContext.K_he).ToUpperInvariant());
            Assert.AreEqual(sk_hs, Convert.ToHexString(context.EncodeRtpContext.K_hs).ToUpperInvariant());

            byte[] rtpExtensionsBytes = Convert.FromHexString(rtpExtensions.Replace(" ", ""));
            byte[] rtpExtensionsMaskBytes = Convert.FromHexString(rtpExtensionsMask.Replace(" ", ""));

            // null payload won't work for F8 cipher
            int ret = context.EncodeRtpContext.ProtectUnprotectRtpHeaderExtensions(null, rtpExtensionsBytes, rtpExtensionsMaskBytes, ssrc, roc, SrtpContext.GenerateRtpIndex(roc, sequenceNumber));
            Assert.AreEqual(0, ret);

            string encryptedExtensions = Convert.ToHexString(rtpExtensionsBytes).ToUpperInvariant();
            Assert.AreEqual(expectedEncryptedExtensions, encryptedExtensions);
        }
    }
}
