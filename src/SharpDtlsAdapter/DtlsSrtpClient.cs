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
using SharpSRTP.DTLS;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;
using SharpDtlsLibClient = SharpDTLS.DtlsClient;
using SharpDtlsSrtp = SharpDTLS.DtlsSrtp;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// DTLS-SRTP client implemented with SharpDTLS: a drop-in replacement for the BouncyCastle based
    /// <see cref="SharpSRTP.DTLSSRTP.DtlsSrtpClient"/>.
    /// </summary>
    public class DtlsSrtpClient : DtlsClient, IDtlsSrtpPeer
    {
        private byte[] _mki;

        public event EventHandler<DtlsSessionStartedEventArgs> OnSessionStarted;
        public int MkiLength { get; private set; } = 0;

        public DtlsSrtpClient(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.ecdsa, short certificateHashAlgorithm = HashAlgorithm.sha256)
            : base(certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        public void SetMKI(byte[] mki)
        {
            if (mki != null && mki.Length > 255)
            {
                throw new ArgumentOutOfRangeException(nameof(mki));
            }

            MkiLength = mki?.Length ?? 0;
            _mki = mki;
        }

        protected virtual ushort[] GetSupportedProtectionProfiles()
        {
            return new ushort[]
            {
                SharpDtlsSrtp.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM,
                SharpDtlsSrtp.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM,
                SharpDtlsSrtp.SRTP_AEAD_AES_256_GCM,
                SharpDtlsSrtp.SRTP_AEAD_ARIA_256_GCM,
                SharpDtlsSrtp.SRTP_AEAD_AES_128_GCM,
                SharpDtlsSrtp.SRTP_AEAD_ARIA_128_GCM,
                SharpDtlsSrtp.SRTP_ARIA_256_CTR_HMAC_SHA1_80,
                SharpDtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_80,
                SharpDtlsSrtp.SRTP_ARIA_128_CTR_HMAC_SHA1_80,
                SharpDtlsSrtp.SRTP_AES128_CM_HMAC_SHA1_32,
                SharpDtlsSrtp.SRTP_ARIA_256_CTR_HMAC_SHA1_32,
                SharpDtlsSrtp.SRTP_ARIA_128_CTR_HMAC_SHA1_32,

                // do not offer NULL profiles to make sure these do not get selected by accident
                //SharpDtlsSrtp.SRTP_NULL_HMAC_SHA1_80,
                //SharpDtlsSrtp.SRTP_NULL_HMAC_SHA1_32
            };
        }

        protected override string GetCertificateCommonName()
        {
            return "WebRTC";
        }

        protected override void ConfigureClient(SharpDtlsLibClient client)
        {
            base.ConfigureClient(client);
            client.SrtpProtectionProfiles = GetSupportedProtectionProfiles();
            client.SrtpMasterKeyIdentifier = _mki;
        }

        protected override void OnHandshakeFinished(IDtlsSecurityParameters securityParameters, DatagramTransport datagramTransport)
        {
            base.OnHandshakeFinished(securityParameters, datagramTransport);
            SrtpSessionContext context = CreateSessionContext(securityParameters);
            OnSessionStarted?.Invoke(this, new DtlsSessionStartedEventArgs(context, securityParameters.PeerCertificate, datagramTransport));
        }

        public virtual SrtpSessionContext CreateSessionContext(IDtlsSecurityParameters securityParameters)
        {
            DtlsSrtpKeys keys = DtlsSrtpProtocol.CreateMasterKeys(securityParameters, ForceUseExtendedMasterSecret);
            return DtlsSrtpProtocol.CreateSrtpClientSessionContext(keys);
        }
    }
}
