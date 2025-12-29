using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;

namespace SharpSRTP.DTLS
{
    public class DTLSClient : DefaultTlsClient
    {
        private Certificate _myCert;
        private AsymmetricKeyParameter _myCertPrivateKey;
        private short _myCertSignatureAlgorithm = SignatureAlgorithm.rsa;
        private short _myCertHashAlgorithm = HashAlgorithm.sha256;

        protected Certificate Certificate => _myCert;
        protected AsymmetricKeyParameter CertificatePrivateKey => _myCertPrivateKey;
        protected short CertificateSignatureAlgorithm => _myCertSignatureAlgorithm;
        protected short CertificateHashAlgorithm => _myCertHashAlgorithm;

        public bool ForceUseExtendedMasterSecret { get; set; } = true;
        public TlsServerCertificate ServerCertificate { get; private set; }

        public event EventHandler<DTLSHandshakeCompletedEventArgs> HandshakeCompleted;

        private TlsSession _session;
        private int _handshakeTimeoutMillis = 0;

        public DTLSClient(TlsSession session = null) : this(new BcTlsCrypto(), session)
        { }

        public DTLSClient(TlsCrypto crypto, TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) : base(crypto)
        {
            this._session = session;
            SetCertificate(certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm);
        }

        public void SetCertificate(Certificate certificate, AsymmetricKeyParameter privateKey, short signatureAlgorithm, short hashAlgorithm)
        {
            _myCert = certificate;
            _myCertPrivateKey = privateKey;
            _myCertSignatureAlgorithm = signatureAlgorithm;
            _myCertHashAlgorithm = hashAlgorithm;
        }

        public override bool RequiresExtendedMasterSecret()
        {
            return ForceUseExtendedMasterSecret;
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return new ProtocolVersion[]
            {
                // ProtocolVersion.DTLSv10,
                ProtocolVersion.DTLSv12,
                //ProtocolVersion.DTLSv13
            };
        }

        protected override int[] GetSupportedCipherSuites()
        {
            // TODO: review

            if (CertificateSignatureAlgorithm == SignatureAlgorithm.rsa)
            {
                return new int[]
                {
                    // TLS 1.2 ciphers:
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
                };
            }
            else if(CertificateSignatureAlgorithm == SignatureAlgorithm.ecdsa)
            {
                // ECDSA certificates require matching cipher suites
                return new int[]
                {
                    // TLS 1.2 ciphers:
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                };
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public override TlsSession GetSessionToResume()
        {
            return this._session;
        }

        public override int GetHandshakeTimeoutMillis() => _handshakeTimeoutMillis;

        public void SetHandshakeTimeoutMillis(int millis) => _handshakeTimeoutMillis = millis;

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            if (Log.DebugEnabled) Log.Debug("DTLS client raised alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                if (Log.DebugEnabled) Log.Debug("> " + message);
            }
            if (cause != null)
            {
                if (Log.DebugEnabled) Log.Debug("", cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if (Log.DebugEnabled) Log.Debug("DTLS client received alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            if(Log.DebugEnabled) Log.Debug("DTLS client negotiated " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new DTlsAuthentication(m_context, this);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                if (Log.DebugEnabled) Log.Debug("Client ALPN: " + protocolName.GetUtf8Decoding());
            }

            TlsSession newSession = m_context.Session;
            if (newSession != null)
            {
                if (newSession.IsResumable)
                {
                    byte[] newSessionID = newSession.SessionID;
                    string hex = ToHexString(newSessionID);

                    if (_session != null && Arrays.AreEqual(_session.SessionID, newSessionID))
                    {
                        if (Log.DebugEnabled) Log.Debug("Client resumed session: " + hex);
                    }
                    else
                    {
                        if (Log.DebugEnabled) Log.Debug("Client established session: " + hex);
                    }

                    this._session = newSession;
                }

                byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
                if (null != tlsServerEndPoint)
                {
                    if (Log.DebugEnabled) Log.Debug("Client 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));
                }

                byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
                if (Log.DebugEnabled) Log.Debug("Client 'tls-unique': " + ToHexString(tlsUnique));
            }

            HandshakeCompleted?.Invoke(this, new DTLSHandshakeCompletedEventArgs(m_context.SecurityParameters));
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetClientExtensions();
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        internal class DTlsAuthentication : TlsAuthentication
        {
            private readonly TlsContext m_context;
            private readonly DTLSClient m_client;

            public DTlsAuthentication(TlsContext context, DTLSClient client)
            {
                this.m_client = client ?? throw new ArgumentNullException(nameof(client));
                this.m_context = context;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();

                if (Log.DebugEnabled) Log.Debug("DTLS client received server certificate chain of length " + chain.Length);
                for (int i = 0; i != chain.Length; i++)
                {
                    X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                    if (Log.DebugEnabled) Log.Debug("DTLS client fingerprint:SHA-256 " + DTLSCertificateUtils.Fingerprint(entry) + " (" + entry.Subject + ")");
                }

                bool isEmpty = serverCertificate == null || serverCertificate.Certificate == null || serverCertificate.Certificate.IsEmpty;

                if (isEmpty)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                TlsCertificate[] certPath = chain;

                // store the certificate for further fingerprint validation
                m_client.ServerCertificate = serverCertificate;

                TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                short[] certificateTypes = certificateRequest.CertificateTypes;
                if (certificateTypes == null || (!Arrays.Contains(certificateTypes, ClientCertificateType.rsa_sign) && !Arrays.Contains(certificateTypes, ClientCertificateType.ecdsa_sign)))
                {
                    return null;
                }

                if(m_client._myCert == null || m_client._myCertPrivateKey == null)
                {
                    return null;
                }

                var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;

                SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

                foreach (SignatureAndHashAlgorithm alg in clientSigAlgs)
                {
                    if (alg.Signature == m_client.CertificateSignatureAlgorithm && alg.Hash == m_client.CertificateSignatureAlgorithm)
                    {
                        signatureAndHashAlgorithm = alg;
                        break;
                    }
                }

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, m_client._myCertPrivateKey, m_client._myCert, signatureAndHashAlgorithm);
            }
        }
    }
}
