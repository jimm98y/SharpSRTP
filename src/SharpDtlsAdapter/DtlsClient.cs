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
using Org.BouncyCastle.X509;
using SharpSRTP.DTLS;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using DtlsVersion = SharpDTLS.DtlsVersion;
using SharpDtlsLibClient = SharpDTLS.DtlsClient;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// DTLS client implemented with SharpDTLS: a drop-in replacement for the BouncyCastle based
    /// <see cref="SharpSRTP.DTLS.DtlsClient"/> that also negotiates DTLS 1.3.
    /// </summary>
    public class DtlsClient : IDtlsPeer
    {
        // How long one receive may block while the handshake is pumped, so timeouts are noticed promptly.
        private const int PumpIntervalMilliseconds = 100;

        private readonly object _syncRoot = new object();
        private X509Certificate _x509Certificate;
        private AsymmetricCipherKeyPair _keyPair;

        public bool AutogenerateCertificate { get; set; } = true;

        public int TimeoutMilliseconds { get; set; } = 20000;
        public Certificate Certificate { get; private set; }
        public AsymmetricKeyParameter CertificatePrivateKey { get; private set; }
        public short CertificateSignatureAlgorithm { get; private set; }
        public short CertificateHashAlgorithm { get; private set; }

        public bool ForceUseExtendedMasterSecret { get; set; } = true;
        public Certificate PeerCertificate { get; private set; }

        /// <summary>The oldest DTLS version offered; DTLS 1.2 by default.</summary>
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>The newest DTLS version offered; DTLS 1.3 by default.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls13;

        public event EventHandler<DtlsHandshakeCompletedEventArgs> OnHandshakeCompleted;
        public event EventHandler<DtlsAlertEventArgs> OnAlert;

        public DtlsClient(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.ecdsa, short certificateHashAlgorithm = HashAlgorithm.sha256)
        {
            SetCertificate(certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm);
        }

        /// <remarks>
        /// SharpDTLS picks the signature scheme from the key, so <paramref name="signatureAlgorithm"/> and
        /// <paramref name="hashAlgorithm"/> are informational.
        /// </remarks>
        public virtual void SetCertificate(Certificate certificate, AsymmetricKeyParameter privateKey, short signatureAlgorithm, short hashAlgorithm)
        {
            Certificate = certificate;
            CertificatePrivateKey = privateKey;
            CertificateSignatureAlgorithm = signatureAlgorithm;
            CertificateHashAlgorithm = hashAlgorithm;
            (_x509Certificate, _keyPair) = Conversions.ToCredentials(certificate, privateKey);
        }

        public virtual void AutogenerateClientCertificate(bool isRsa)
        {
            var cert = DtlsCertificateUtils.GenerateCertificate(GetCertificateCommonName(), DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), isRsa);
            SetCertificate(cert.Certificate, cert.PrivateKey, isRsa ? SignatureAlgorithm.rsa : SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);
        }

        protected virtual string GetCertificateCommonName()
        {
            return "DTLS";
        }

        /// <summary>Applies further settings to the SharpDTLS client before the handshake begins.</summary>
        protected virtual void ConfigureClient(SharpDtlsLibClient client)
        { }

        /// <summary>Called after <see cref="OnHandshakeCompleted"/>, before <see cref="DoHandshake"/> returns.</summary>
        protected virtual void OnHandshakeFinished(IDtlsSecurityParameters securityParameters, DatagramTransport datagramTransport)
        { }

        public virtual IDtlsTransport DoHandshake(out string handshakeError, DatagramTransport datagramTransport, IDtlsRequest request = null)
        {
            if (datagramTransport == null)
            {
                throw new ArgumentNullException(nameof(datagramTransport));
            }

            lock (_syncRoot)
            {
                // SharpDTLS needs the certificate before the ClientHello, while BouncyCastle creates it on CertificateRequest.
                if ((Certificate == null || CertificatePrivateKey == null) && AutogenerateCertificate)
                {
                    AutogenerateClientCertificate(false);
                }

                var transport = new ClientTransportAdapter(datagramTransport);
                var client = new SharpDtlsLibClient(transport)
                {
                    MinimumVersion = MinimumVersion,
                    MaximumVersion = MaximumVersion,
                    // Accept any certificate, as the BouncyCastle client does: the caller validates PeerCertificate (e.g. its fingerprint).
                    ServerCertificateValidator = (certificate, chain) => true,
                    ClientCertificate = _x509Certificate,
                    ClientCertificateKeyPair = _keyPair,
                };

                var received = new ConcurrentQueue<byte[]>();
                var state = new HandshakeState();
                client.HandshakeFinished += (_, _) => state.Finished = true;
                client.Failed += (_, ex) => state.Error ??= ex;
                client.ApplicationDataReceived += (_, data) => received.Enqueue(data);
                client.AlertReceived += (_, alert) => OnAlert?.Invoke(this, Conversions.ToAlert(alert));
                ConfigureClient(client);

                try
                {
                    client.BeginHandshake();

                    var stopwatch = Stopwatch.StartNew();
                    while (!state.Finished && state.Error == null)
                    {
                        int remaining = TimeoutMilliseconds - (int)stopwatch.ElapsedMilliseconds;
                        if (remaining <= 0)
                        {
                            throw new TimeoutException("DTLS handshake timed out.");
                        }

                        transport.Pump(Math.Min(remaining, PumpIntervalMilliseconds));
                    }

                    if (state.Error != null)
                    {
                        throw state.Error;
                    }

                    var connection = client.Connection;
                    if (ForceUseExtendedMasterSecret && !connection.IsExtendedMasterSecret)
                    {
                        throw new InvalidOperationException("The server did not negotiate the extended master secret.");
                    }

                    var securityParameters = new SharpDtlsSecurityParameters(connection);
                    PeerCertificate = securityParameters.PeerCertificate;
                    OnHandshakeCompleted?.Invoke(this, new DtlsHandshakeCompletedEventArgs(securityParameters));
                    OnHandshakeFinished(securityParameters, datagramTransport);

                    handshakeError = null;
                    return new SharpDtlsTransport(connection, datagramTransport, transport.Pump, received);
                }
                catch (Exception ex)
                {
                    client.Close();
                    handshakeError = ex.Message;
                    return null;
                }
            }
        }

        private sealed class HandshakeState
        {
            public volatile bool Finished;
            public volatile Exception Error;
        }
    }
}
