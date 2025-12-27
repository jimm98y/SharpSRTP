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

        protected Certificate Certificate => _myCert;
        protected AsymmetricKeyParameter CertificatePrivateKey => _myCertPrivateKey;
        protected short CertificateSignatureAlgorithm => _myCertSignatureAlgorithm;

        public TlsServerCertificate ServerCertificate { get; private set; }

        public event EventHandler<DTLSHandshakeCompletedEventArgs> HandshakeCompleted;

        private TlsSession _session;
        private int _handshakeTimeoutMillis = 0;

        public DTLSClient(TlsSession session = null) : this(new BcTlsCrypto(), session)
        { }

        public DTLSClient(TlsCrypto crypto, TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short signatureAlgorithm = SignatureAlgorithm.rsa) : base(crypto)
        {
            this._session = session;
            SetCertificate(certificate, privateKey, signatureAlgorithm);
        }

        public void SetCertificate(Certificate certificate, AsymmetricKeyParameter privateKey, short signatureAlgorithm)
        {
            _myCert = certificate;
            _myCertPrivateKey = privateKey;
            _myCertSignatureAlgorithm = signatureAlgorithm;
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
            return new MyTlsAuthentication(m_context, this);
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

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.DTLSv12.Only();
        }

        internal class MyTlsAuthentication : TlsAuthentication
        {
            private readonly TlsContext m_context;
            private readonly DTLSClient m_client;

            public MyTlsAuthentication(TlsContext context, DTLSClient client)
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
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    if (Log.DebugEnabled) Log.Debug("DTLS client fingerprint:SHA-256 " + DTLSCertificateUtils.Fingerprint(entry) + " (" + entry.Subject + ")");
                }

                bool isEmpty = serverCertificate == null || serverCertificate.Certificate == null || serverCertificate.Certificate.IsEmpty;

                if (isEmpty)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                // TODO: certificate chain validation
                TlsCertificate[] certPath = chain;

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
                    if (alg.Signature == m_client._myCertSignatureAlgorithm)
                    {
                        // Just grab the first one we find
                        signatureAndHashAlgorithm = alg;
                        break;
                    }
                }

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, m_client._myCertPrivateKey, m_client._myCert, signatureAndHashAlgorithm);
            }
        }
    }
}
