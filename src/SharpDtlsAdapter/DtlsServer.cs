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
using System.Net;
using Dtls12SessionCache = SharpDTLS.Protocol12.Dtls12SessionCache;
using DtlsVersion = SharpDTLS.DtlsVersion;
using IServerTransport = SharpDTLS.UDP.IServerTransport;
using SessionTicketKeys = SharpDTLS.SessionTicketKeys;
using SharpDtlsLibServer = SharpDTLS.DtlsServer;
using TlsConnectionBase = SharpDTLS.TlsConnectionBase;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// DTLS server implemented with SharpDTLS: a drop-in replacement for the BouncyCastle based
    /// <see cref="SharpSRTP.DTLS.DtlsServer"/> that also negotiates DTLS 1.3.
    /// </summary>
    /// <remarks>
    /// As with BouncyCastle, every <see cref="DoHandshake"/> runs its own SharpDTLS server, referenced only from the
    /// <see cref="IDtlsTransport"/> it returns: dropping that releases the connection. Handshakes run in parallel, and
    /// session tickets and the DTLS 1.2 session cache are shared, so sessions resume across connections.
    /// </remarks>
    public class DtlsServer : IDtlsServerPeer
    {
        // How long one receive may block while the handshake is pumped, so timeouts are noticed promptly.
        private const int PumpIntervalMilliseconds = 100;

        private readonly object _syncRoot = new object();
        private readonly SessionTicketKeys _ticketKeys = new SessionTicketKeys();
        private readonly Dtls12SessionCache _sessionCache = new Dtls12SessionCache();
        private readonly VerifierServerTransport _verifierTransport = new VerifierServerTransport();
        private SharpDtlsLibServer _verifier;
        private X509Certificate _x509Certificate;
        private AsymmetricCipherKeyPair _keyPair;

        public int TimeoutMilliseconds { get; set; } = 20000;

        public Certificate Certificate { get; private set; }
        public AsymmetricKeyParameter CertificatePrivateKey { get; private set; }
        public short CertificateSignatureAlgorithm { get; private set; }
        public short CertificateHashAlgorithm { get; private set; }

        public bool ForceUseExtendedMasterSecret { get; set; } = true;

        /// <summary>Request and require a client certificate, as the BouncyCastle server does.</summary>
        public bool RequireClientCertificate { get; set; } = true;

        /// <summary>The oldest DTLS version accepted; DTLS 1.2 by default.</summary>
        public ushort MinimumVersion { get; set; } = DtlsVersion.Dtls12;

        /// <summary>The newest DTLS version accepted; DTLS 1.3 by default.</summary>
        public ushort MaximumVersion { get; set; } = DtlsVersion.Dtls13;

        public event EventHandler<DtlsHandshakeCompletedEventArgs> OnHandshakeCompleted;
        public event EventHandler<DtlsAlertEventArgs> OnAlert;

        public DtlsServer(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.ecdsa, short certificateHashAlgorithm = HashAlgorithm.sha256)
        {
            if (certificate == null || privateKey == null)
            {
                // generate default self-signed certificate - SRTP_AEAD_AES_256_GCM requires ECDsa
                AutogenerateClientCertificate(false);
            }
            else
            {
                SetCertificate(certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm);
            }
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

        /// <summary>Applies further settings to each SharpDTLS server, including the one verifying cookies.</summary>
        protected virtual void ConfigureServer(SharpDtlsLibServer server)
        { }

        /// <summary>Called after <see cref="OnHandshakeCompleted"/>, before <see cref="DoHandshake"/> returns.</summary>
        protected virtual void OnHandshakeFinished(IDtlsSecurityParameters securityParameters, DatagramTransport datagramTransport)
        { }

        /// <remarks>
        /// The cookie is checked by a SharpDTLS server that never creates connections, set up with the settings of the
        /// first call; the server <see cref="DoHandshake"/> creates accepts it.
        /// </remarks>
        public virtual IDtlsRequest VerifyRequest(EndPoint remoteEndpoint, byte[] data, int offset, int length, DatagramSender sender)
        {
            if (remoteEndpoint is not IPEndPoint ip)
            {
                throw new ArgumentException("An IP endpoint is required.", nameof(remoteEndpoint));
            }

            // a copy: callers may reuse their instance for the next datagram
            var endpoint = new IPEndPoint(ip.Address, ip.Port);
            lock (_syncRoot)
            {
                _verifier ??= CreateServer(_verifierTransport);
                _verifierTransport.Sender = sender;
                try
                {
                    return _verifier.VerifyClientHello(endpoint, data.AsSpan(offset, length).ToArray()) ? new SharpDtlsRequest(endpoint) : null;
                }
                finally
                {
                    _verifierTransport.Sender = null;
                }
            }
        }

        public virtual IDtlsTransport DoHandshake(out string handshakeError, DatagramTransport datagramTransport, IDtlsRequest request = null)
        {
            if (datagramTransport == null)
            {
                throw new ArgumentNullException(nameof(datagramTransport));
            }

            var transport = new PeerServerTransport(datagramTransport, PeerServerTransport.EndpointOf(datagramTransport, request));
            var server = CreateServer(transport);
            var state = new HandshakeState();
            var received = new ConcurrentQueue<byte[]>();
            server.HandshakeFinished += (_, connection) => state.Connection = connection;
            server.ConnectionClosed += (_, _) => state.Closed = true;
            server.ApplicationDataReceived += (_, e) => received.Enqueue(e.Data);
            server.AlertReceived += (_, e) => OnAlert?.Invoke(this, Conversions.ToAlert(e.Description));

            try
            {
                var stopwatch = Stopwatch.StartNew();
                while (state.Connection == null && !state.Closed)
                {
                    int remaining = TimeoutMilliseconds - (int)stopwatch.ElapsedMilliseconds;
                    if (remaining <= 0)
                    {
                        throw new TimeoutException("DTLS handshake timed out.");
                    }

                    transport.Pump(Math.Min(remaining, PumpIntervalMilliseconds));
                }

                var connection = state.Connection;
                if (connection == null)
                {
                    throw new InvalidOperationException("The DTLS handshake failed.");
                }

                if (ForceUseExtendedMasterSecret && !connection.IsExtendedMasterSecret)
                {
                    throw new InvalidOperationException("The client did not negotiate the extended master secret.");
                }

                var securityParameters = new SharpDtlsSecurityParameters(connection);
                OnHandshakeCompleted?.Invoke(this, new DtlsHandshakeCompletedEventArgs(securityParameters));
                OnHandshakeFinished(securityParameters, datagramTransport);

                handshakeError = null;
                return new SharpDtlsTransport(connection, datagramTransport, transport.Pump, received);
            }
            catch (Exception ex)
            {
                server.Close(transport.Endpoint);
                handshakeError = ex.Message;
                return null;
            }
        }

        private SharpDtlsLibServer CreateServer(IServerTransport transport)
        {
            var server = new SharpDtlsLibServer(transport, _keyPair, _x509Certificate)
            {
                MinimumVersion = MinimumVersion,
                MaximumVersion = MaximumVersion,
                RequireClientCertificate = RequireClientCertificate,
                // Accept any certificate, as the BouncyCastle server does: the caller validates the peer certificate (e.g. its fingerprint).
                ClientCertificateValidator = (certificate, chain) => true,
                // shared, so a session resumes on whichever server runs the next handshake
                TicketKeys = _ticketKeys,
                SessionCache = _sessionCache,
            };
            ConfigureServer(server);
            return server;
        }

        private sealed class HandshakeState
        {
            public volatile TlsConnectionBase Connection;
            public volatile bool Closed;
        }
    }
}
