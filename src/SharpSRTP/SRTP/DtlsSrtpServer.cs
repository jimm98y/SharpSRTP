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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpSRTP.DTLS;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public class DtlsSrtpServer : DtlsServer, IDtlsSrtpPeer
    {
        private UseSrtpData _srtpData;
        
        public DtlsSrtpServer(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) 
            : this(new BcTlsCrypto(), certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        public DtlsSrtpServer(TlsCrypto crypto, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) 
            : base(crypto, certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        protected virtual int[] GetSupportedProtectionProfiles()
        {
            return new int[] 
            {
                ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_256_GCM,
                ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_32,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_32,

                ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_256_GCM,
                ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM,

                ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32,

                ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32
            };
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            base.ProcessClientExtensions(clientExtensions);

            UseSrtpData clientSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(clientExtensions);

            int[] serverSupportedProfiles = GetSupportedProtectionProfiles();
            int[] mutuallySupportedProfiles = clientSrtpExtension.ProtectionProfiles.Where(x => serverSupportedProfiles.Contains(x)).ToArray();
            if (mutuallySupportedProfiles.Length == 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            int selectedProfile = mutuallySupportedProfiles.OrderBy(x => Array.IndexOf(serverSupportedProfiles, x)).First(); // Choose the highest priority profile supported by the server
            _srtpData = new UseSrtpData(new int[] { selectedProfile }, clientSrtpExtension.Mki); // Server must return only a single selected profile
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            var extensions = base.GetServerExtensions();
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _srtpData);
            return extensions;
        }

        public virtual SrtpSessionContext CreateSessionContext(SecurityParameters securityParameters)
        {
            // this should only be called from OnHandshakeCompleted so we should still have _srtpData from the connection
            if (m_context == null)
                throw new InvalidOperationException();

            SrtpKeys keys = DtlsSrtpProtocol.GenerateMasterKeys(_srtpData.ProtectionProfiles[0], _srtpData.Mki, securityParameters, ForceUseExtendedMasterSecret);
            var encodeRtpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTP);
            var encodeRtcpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTCP);
            var decodeRtpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTP);
            var decodeRtcpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTCP);
            return new SrtpSessionContext(encodeRtpContext, decodeRtpContext, encodeRtcpContext, decodeRtcpContext);
        }
    }
}
