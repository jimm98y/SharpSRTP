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
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using System;
using System.Net;
using TlsConnectionBase = SharpDTLS.TlsConnectionBase;

namespace SharpSRTP.DTLS
{
    /// <summary>
    /// <see cref="IDtlsSecurityParameters"/> over a SharpDTLS connection of any DTLS version.
    /// </summary>
    public sealed class SharpDtlsSecurityParameters : IDtlsSecurityParameters
    {
        private static readonly BcTlsCrypto Crypto = new BcTlsCrypto();

        public TlsConnectionBase Connection { get; }

        public SharpDtlsSecurityParameters(TlsConnectionBase connection)
        {
            this.Connection = connection ?? throw new ArgumentNullException(nameof(connection));
            this.LocalCertificate = ToCertificate(connection.LocalCertificate);
            this.PeerCertificate = ToCertificate(connection.PeerCertificate);
        }

        public int NegotiatedVersion => Connection.NegotiatedVersion;
        public int CipherSuite => Connection.NegotiatedCipherSuite;
        public bool IsExtendedMasterSecret => Connection.IsExtendedMasterSecret;
        public bool IsResumed => Connection.IsResumed;
        public byte[] ClientRandom => Connection.ClientRandom;
        public byte[] ServerRandom => Connection.ServerRandom;
        public string ApplicationProtocol => Connection.ApplicationProtocol;
        public Certificate LocalCertificate { get; }
        public Certificate PeerCertificate { get; }
        public int? SrtpProtectionProfile => Connection.SelectedSrtpProtectionProfile;
        public byte[] SrtpMki => Connection.SelectedSrtpMki;

        public byte[] ExportKeyingMaterial(string label, byte[] context, int length) => Connection.ExportKeyingMaterial(label, context, length);

        internal static Certificate ToCertificate(X509Certificate certificate)
        {
            return certificate == null ? null : new Certificate(new TlsCertificate[] { new BcTlsCertificate(Crypto, certificate.GetEncoded()) });
        }
    }

    internal sealed class SharpDtlsRequest : IDtlsRequest
    {
        public EndPoint RemoteEndpoint { get; }

        public SharpDtlsRequest(EndPoint remoteEndpoint)
        {
            this.RemoteEndpoint = remoteEndpoint;
        }
    }
}
