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

using Org.BouncyCastle.Tls;
using System;
using System.Net;

namespace SharpSRTP.DTLS
{
    /// <summary>
    /// <see cref="IDtlsSecurityParameters"/> over BouncyCastle <see cref="SecurityParameters"/> (DTLS 1.2).
    /// </summary>
    /// <remarks>
    /// BouncyCastle exports keying material only while the handshake completes, so <see cref="ExportKeyingMaterial"/>
    /// works inside <see cref="IDtlsPeer.OnHandshakeCompleted"/> (where DTLS-SRTP derives its keys) and throws afterwards.
    /// </remarks>
    public class BcDtlsSecurityParameters : IDtlsSecurityParameters
    {
        private readonly TlsContext _context;

        /// <param name="context">The connection's context.</param>
        /// <param name="srtpData">The negotiated use_srtp extension, or null.</param>
        public BcDtlsSecurityParameters(TlsContext context, UseSrtpData srtpData = null)
        {
            this._context = context ?? throw new ArgumentNullException(nameof(context));

            // BouncyCastle clears the handshake's security parameters after the handshake: copy what we expose.
            SecurityParameters securityParameters = context.SecurityParameters;
            NegotiatedVersion = securityParameters.NegotiatedVersion.FullVersion;
            CipherSuite = securityParameters.CipherSuite;
            IsExtendedMasterSecret = securityParameters.IsExtendedMasterSecret;
            IsResumed = securityParameters.IsResumedSession;
            ClientRandom = securityParameters.ClientRandom;
            ServerRandom = securityParameters.ServerRandom;
            ApplicationProtocol = securityParameters.ApplicationProtocol?.GetUtf8Decoding();
            LocalCertificate = securityParameters.LocalCertificate;
            PeerCertificate = securityParameters.PeerCertificate;
            SrtpProtectionProfile = srtpData?.ProtectionProfiles[0];
            SrtpMki = srtpData == null ? null : srtpData.Mki ?? Array.Empty<byte>();
        }

        public int NegotiatedVersion { get; }
        public int CipherSuite { get; }
        public bool IsExtendedMasterSecret { get; }
        public bool IsResumed { get; }
        public byte[] ClientRandom { get; }
        public byte[] ServerRandom { get; }
        public string ApplicationProtocol { get; }
        public Certificate LocalCertificate { get; }
        public Certificate PeerCertificate { get; }
        public int? SrtpProtectionProfile { get; }
        public byte[] SrtpMki { get; }

        public byte[] ExportKeyingMaterial(string label, byte[] context, int length) => _context.ExportKeyingMaterial(label, context, length);
    }

    internal class BcDtlsRequest : IDtlsRequest
    {
        public DtlsRequest Request { get; }
        public EndPoint RemoteEndpoint { get; }

        public BcDtlsRequest(DtlsRequest request, EndPoint remoteEndpoint)
        {
            this.Request = request;
            this.RemoteEndpoint = remoteEndpoint;
        }
    }
}
