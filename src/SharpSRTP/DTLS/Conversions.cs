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
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Tls;
using System;
using System.Security.Cryptography.X509Certificates;
using SharpDtlsAlert = SharpDTLS.AlertDescription;

namespace SharpSRTP.DTLS
{
    internal static class Conversions
    {
        /// <summary>
        /// The end-entity certificate and key SharpDTLS authenticates with, as a server or a client: the certificate's DER,
        /// the key as PKCS#8. Null without either.
        /// </summary>
        public static SharpDTLS.ServerCredentials ToCredentials(Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            if (certificate == null || certificate.IsEmpty || privateKey == null)
            {
                return null;
            }

            byte[] der = certificate.GetCertificateAt(0).GetEncoded();
#if NET9_0_OR_GREATER
            var x509 = X509CertificateLoader.LoadCertificate(der);
#else
            var x509 = new X509Certificate2(der);
#endif
            return new SharpDTLS.ServerCredentials(x509, PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded());
        }

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
