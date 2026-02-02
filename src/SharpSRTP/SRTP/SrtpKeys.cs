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

using System;

namespace SharpSRTP.SRTP
{
    public class SrtpKeys
    {
        public SrtpProtectionProfileConfiguration ProtectionProfile { get; }

        public ReadOnlyMemory<byte> Mki { get; }


        public ReadOnlyMemory<byte> MasterKey { get; }
        public ReadOnlyMemory<byte> MasterSalt { get; }
        public ReadOnlyMemory<byte> MasterKeySalt { get; }

        public SrtpKeys(SrtpProtectionProfileConfiguration protectionProfile, ReadOnlyMemory<byte> masterKeySalt = default, ReadOnlyMemory<byte> mki = default)
        {
            Throw.IfNull(protectionProfile);

            this.ProtectionProfile = protectionProfile;

            int requiredLen = (protectionProfile.CipherKeyLength + protectionProfile.CipherSaltLength) >> 3;
            if (masterKeySalt.IsEmpty)
            {
                this.MasterKeySalt = new byte[requiredLen];
            }
            else
            {
                if (masterKeySalt.Length != requiredLen)
                {
                    Throw.ArgumentException("masterKeySalt length does not match profile requirements", nameof(masterKeySalt));
                }

                this.MasterKeySalt = masterKeySalt;
            }

            this.MasterKey = MasterKeySalt.Slice(0, protectionProfile.CipherKeyLength >> 3);
            this.MasterSalt = MasterKeySalt.Slice(protectionProfile.CipherKeyLength >> 3);
            this.Mki = mki;
        }
    }
}
