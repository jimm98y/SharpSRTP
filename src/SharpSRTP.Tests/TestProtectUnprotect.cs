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
    [TestClass]
    public class TestProtectUnprotect
    {
        [DataRow("n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi", "80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0", "80e1000103cb6bc84218a6a3cf77c0bc864411afc82ac978b1087b699bf51892b46152bcf95963dbc69f7efbb776c79a0daa3e2e7ae8a3ceda005fb29b068d099d0b0a103ae0bc9ae62b55c0c8dca25583478377f2bb310f0371a2ada32a119e96a84c796b9376a093409e21a7b16bafedbc4fffadabe5f770e895ec36b8de959819aac706aba8788ba9da2fd3f58bd43796fd51124e92117d98575cc82d302741a8be3c9234bafeb42d2c52ebd9e6edfcb1e7e01fb40131758c9d1181525b1c02e35cc34b46e0aaf1df4dc931036aaf4f9044b47058d22008395596e8000b4a7def6aa97a989e76f0c88ba939313459373a6f")]
        [TestMethod]
        public void Test_Srtp_Protect_Unprotect(string masterKeySalt, string rtp, string srtp)
        {
            byte[] masterKeySaltBytes = Convert.FromBase64String(masterKeySalt);
            byte[] rtpBytes = Convert.FromHexString(rtp);
            byte[] srtpBytes = rtpBytes.Concat(new byte[10]).ToArray();

            byte[] MKI = null;
            var keys = SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, MKI, masterKeySaltBytes);
            var context = SrtpProtocol.CreateSrtpSessionContext(keys);
            int ret = context.EncodeRtpContext.ProtectRtp(srtpBytes, rtpBytes.Length, out int len);

            string srtpString = Convert.ToHexString(srtpBytes.Take(len).ToArray()).ToLowerInvariant();
            Assert.AreEqual(srtp, srtpString);

            context.DecodeRtpContext.UnprotectRtp(srtpBytes, srtpBytes.Length, out int olen);

            string rtpString = Convert.ToHexString(srtpBytes.Take(olen).ToArray()).ToLowerInvariant();
            Assert.AreEqual(rtp, rtpString);
        }
    }
}
