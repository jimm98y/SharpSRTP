using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;

namespace SharpSRTP.DTLS
{
    public class DTLSServer : DefaultTlsServer
    {
        private Certificate _myCert;
        private AsymmetricKeyParameter _myCertPrivateKey;
        protected short _myCertCertificateAlgorithm = SignatureAlgorithm.rsa;

        protected Certificate Certificate => _myCert;
        protected AsymmetricKeyParameter CertificatePrivateKey => _myCertPrivateKey;

        public Certificate ClientCertificate { get; private set; }

        public event EventHandler<DTLSHandshakeCompletedEventArgs> HandshakeCompleted;

        public DTLSServer(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short signatureAlgorithm = SignatureAlgorithm.rsa) : this(new BcTlsCrypto())
        {
            SetCertificate(certificate, privateKey, signatureAlgorithm);
        }

        public DTLSServer(TlsCrypto crypto) : base(crypto)
        {  }

        public void SetCertificate(Certificate certificate, AsymmetricKeyParameter privateKey, short signatureAlgorithm)
        {
            _myCert = certificate;
            _myCertPrivateKey = privateKey;
            _myCertCertificateAlgorithm = signatureAlgorithm;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            Log.Debug("DTLS server raised alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
            
            if (message != null)
            {
                Log.Debug("> " + message);
            }
            if (cause != null)
            {
                Log.Debug("", cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if(Log.DebugEnabled) Log.Debug("DTLS server received alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();
            if (Log.DebugEnabled) Log.Debug("DTLS server negotiated " + serverVersion);
            return serverVersion;
        }

        public override CertificateRequest GetCertificateRequest()
        {
            short[] certificateTypes = new short[]{ ClientCertificateType.ecdsa_sign, ClientCertificateType.rsa_sign };

            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(m_context.ServerVersion))
            {
                serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
            }

            return new CertificateRequest(certificateTypes, serverSigAlgs, null);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            ClientCertificate = clientCertificate;

            TlsCertificate[] chain = clientCertificate.GetCertificateList();

            Log.Debug("DTLS server received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                Log.Debug("    fingerprint:SHA-256 " + DTLSCertificateUtils.Fingerprint(entry) + " (" + entry.Subject + ")");
            }

            bool isEmpty = (clientCertificate == null || clientCertificate.IsEmpty);

            if (isEmpty)
                return;

            // TODO review
            /*
            string[] trustedCertResources = new string[]{ "x509-client-dsa.pem", "x509-client-ecdh.pem",
                "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem",
                "x509-client-ml_dsa_44.pem", "x509-client-ml_dsa_65.pem", "x509-client-ml_dsa_87.pem",
                "x509-client-rsa_pss_256.pem", "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",
                "x509-client-rsa.pem" };

            TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0], trustedCertResources);

            if (null == certPath)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
            */
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Log.Debug("Server ALPN: " + protocolName.GetUtf8Decoding());
            }

            byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            Log.Debug("Server 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));

            byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
            Log.Debug("Server 'tls-unique': " + ToHexString(tlsUnique));

            HandshakeCompleted?.Invoke(this, new DTLSHandshakeCompletedEventArgs(m_context.SecurityParameters));
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);
            
            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.DTLSv12.Only();
        }

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            IList<SignatureAndHashAlgorithm> clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

            foreach (SignatureAndHashAlgorithm alg in clientSigAlgs)
            {
                if (alg.Signature == SignatureAlgorithm.ecdsa)
                {
                    // Just grab the first one we find
                    signatureAndHashAlgorithm = alg;
                    break;
                }
            }

            if (_myCert == null || _myCertPrivateKey == null)
            {
                throw new InvalidOperationException("DTLS server ECDsa certificate not set!");
            }

            if(_myCertCertificateAlgorithm != SignatureAlgorithm.ecdsa)
            {
                throw new InvalidOperationException("DTLS server ECDsa certificate algorithm mismatch!");
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _myCertPrivateKey, _myCert, signatureAndHashAlgorithm);
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            IList<SignatureAndHashAlgorithm> clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

            foreach (SignatureAndHashAlgorithm alg in clientSigAlgs)
            {
                if (alg.Signature == SignatureAlgorithm.rsa)
                {
                    // Just grab the first one we find
                    signatureAndHashAlgorithm = alg;
                    break;
                }
            }

            if (_myCert == null || _myCertPrivateKey == null)
            {
                throw new InvalidOperationException("DTLS server RSA certificate not set!");
            }

            if (_myCertCertificateAlgorithm != SignatureAlgorithm.rsa)
            {
                throw new InvalidOperationException("DTLS server RSA certificate algorithm mismatch!");
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _myCertPrivateKey, _myCert, signatureAndHashAlgorithm);
        }
    }
}