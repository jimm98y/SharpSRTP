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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpDTLS;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using SharpDtlsAlert = SharpDTLS.AlertDescription;

namespace SharpSRTP.DTLS
{
    /// <summary>The .NET certificates of the public API, to and from BouncyCastle's and SharpDTLS's.</summary>
    internal static class Conversions
    {
        private static readonly BcTlsCrypto Crypto = new BcTlsCrypto();

        public static X509Certificate2 Load(byte[] der)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(der);
#else
            return new X509Certificate2(der);
#endif
        }

        /// <summary>Credentials of a certificate made here: its DER, the key as PKCS#8; a server's or a client's.</summary>
        public static TransportCertificate ToCredentials(byte[] certificateDer, AsymmetricKeyParameter privateKey)
            => new TransportCertificate(Load(certificateDer), PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded());

        /// <summary>
        /// The chain and key BouncyCastle's DTLS authenticates with; the key must be exportable (or given as PKCS#8).
        /// </summary>
        public static (Certificate Certificate, AsymmetricKeyParameter PrivateKey) ToBc(TransportCertificate credentials)
        {
            if (credentials == null)
            {
                return (null, null);
            }

            var entries = new[] { credentials.Certificate }.Concat(credentials.IntermediateCertificates)
                .Select(c => new CertificateEntry(Crypto.CreateCertificate(c.RawData), null)).ToArray();
            // certificateRequestContext = null for DTLS 1.2
            return (new Certificate(null, entries), PrivateKeyFactory.CreateKey(credentials.ExportPkcs8PrivateKey()));
        }

        /// <summary>The end-entity certificate of a BouncyCastle chain, or null.</summary>
        public static X509Certificate2 ToX509(Certificate certificate)
            => certificate == null || certificate.IsEmpty ? null : Load(certificate.GetCertificateAt(0).GetEncoded());

        /// <summary>The TLS 1.2 signature and hash algorithms of a key: ECDSA's hash of its curve's size, RSA's SHA-256.</summary>
        public static (short Signature, short Hash) AlgorithmsOf(AsymmetricKeyParameter privateKey) => privateKey switch
        {
            null => (SignatureAlgorithm.ecdsa, HashAlgorithm.sha256),
            RsaKeyParameters => (SignatureAlgorithm.rsa, HashAlgorithm.sha256),
            ECPrivateKeyParameters ec => (SignatureAlgorithm.ecdsa, ec.Parameters.Curve.FieldSize > 384 ? HashAlgorithm.sha512 : ec.Parameters.Curve.FieldSize > 256 ? HashAlgorithm.sha384 : HashAlgorithm.sha256),
            _ => throw new NotSupportedException("BouncyCastle's DTLS signs with RSA or ECDSA keys."),
        };

        public static DtlsAlertEventArgs ToAlert(SharpDtlsAlert description)
        {
            TlsAlertTypesEnum alertType = Enum.IsDefined(typeof(TlsAlertTypesEnum), (int)description) ? (TlsAlertTypesEnum)(int)description : TlsAlertTypesEnum.Unassigned;

            // SharpDTLS reports only the description: close_notify and user_canceled are warnings, the rest end the connection.
            TlsAlertLevelsEnum level = description == SharpDtlsAlert.CloseNotify || description == SharpDtlsAlert.UserCanceled ? TlsAlertLevelsEnum.Warn : TlsAlertLevelsEnum.Fatal;

            if (Log.DebugEnabled)
            {
                Log.Debug($"DTLS received alert: {level}, {description}");
            }

            return new DtlsAlertEventArgs(level, alertType, description.ToString());
        }
    }
}
