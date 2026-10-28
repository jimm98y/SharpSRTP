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

namespace SharpSRTP.DTLS
{
    /// <summary>
    /// Parameters negotiated by a DTLS handshake, independent of the DTLS library that negotiated them.
    /// </summary>
    public interface IDtlsSecurityParameters
    {
        /// <summary>Negotiated protocol version as on the wire, e.g. 0xFEFD for DTLS 1.2 or 0xFEFC for DTLS 1.3.</summary>
        int NegotiatedVersion { get; }

        /// <summary>Negotiated cipher suite id.</summary>
        int CipherSuite { get; }

        /// <summary>Extended master secret (RFC 7627) for DTLS 1.2, always true for DTLS 1.3 whose keys are bound to the transcript.</summary>
        bool IsExtendedMasterSecret { get; }

        bool IsResumed { get; }

        byte[] ClientRandom { get; }

        byte[] ServerRandom { get; }

        /// <summary>Application protocol negotiated with ALPN, or null.</summary>
        string ApplicationProtocol { get; }

        /// <summary>The certificate this side authenticated with, or null.</summary>
        Certificate LocalCertificate { get; }

        /// <summary>The certificate the peer authenticated with, or null.</summary>
        Certificate PeerCertificate { get; }

        /// <summary>SRTP protection profile negotiated with use_srtp, or null when use_srtp was not negotiated.</summary>
        int? SrtpProtectionProfile { get; }

        /// <summary>SRTP Master Key Identifier negotiated with use_srtp; empty when no MKI is used.</summary>
        byte[] SrtpMki { get; }

        /// <summary>Keying material exporter (RFC 5705 for DTLS 1.2, RFC 8446 §7.5 for DTLS 1.3).</summary>
        byte[] ExportKeyingMaterial(string label, byte[] context, int length);
    }
}
