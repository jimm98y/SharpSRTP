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

using SharpSRTP.DTLSSRTP;
using System;

namespace SharpSRTP.SRTP
{
    public class SrtpKeys
    {
        public int ProtectionProfile { get; }
        public byte[] Mki { get; }

        public byte[] ClientWriteMasterKey { get; }
        public byte[] ClientWriteMasterSalt { get; }
        public byte[] ServerWriteMasterKey { get; }
        public byte[] ServerWriteMasterSalt { get; }

        public SrtpKeys(int protectionProfile, byte[] mki = null)
        {
            if (!DtlsSrtpProtocol.DtlsProtectionProfiles.ContainsKey(protectionProfile))
                throw new NotSupportedException($"Unsupported protectionProfile {protectionProfile}");

            SrtpProtectionProfileConfiguration srtpSecurityParams = DtlsSrtpProtocol.DtlsProtectionProfiles[protectionProfile];

            this.ProtectionProfile = protectionProfile;
            this.Mki = mki;

            int cipherKeyLen = srtpSecurityParams.CipherKeyLength >> 3;
            int cipherSaltLen = srtpSecurityParams.CipherSaltLength >> 3;

            this.ClientWriteMasterKey = new byte[cipherKeyLen];
            this.ClientWriteMasterSalt = new byte[cipherSaltLen];
            this.ServerWriteMasterKey = new byte[cipherKeyLen];
            this.ServerWriteMasterSalt = new byte[cipherSaltLen];
        }
    }
}
