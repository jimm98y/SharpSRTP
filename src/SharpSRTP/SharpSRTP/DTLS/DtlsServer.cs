using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpSRTP.DTLS
{
    public class DtlsServer : DefaultTlsServer
    {
        protected Certificate _myCert;
        protected AsymmetricKeyParameter _myCertKey;

        public Certificate ClientCertificate { get; private set; }

        public event EventHandler<DtlsHandshakeCompletedEventArgs> HandshakeCompleted;

        public DtlsServer() : this(new BcTlsCrypto())
        {
        }

        public DtlsServer(TlsCrypto crypto) : base(crypto)
        {
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS server raised alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
            
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS server received alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();
            Console.WriteLine("DTLS server negotiated " + serverVersion);
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

            Console.WriteLine("DTLS server received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                Console.WriteLine("    fingerprint:SHA-256 " + DtlsCertificateUtils.Fingerprint(entry) + " (" + entry.Subject + ")");
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
                Console.WriteLine("Server ALPN: " + protocolName.GetUtf8Decoding());
            }

            byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            Console.WriteLine("Server 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));

            byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
            Console.WriteLine("Server 'tls-unique': " + ToHexString(tlsUnique));

            HandshakeCompleted?.Invoke(this, new DtlsHandshakeCompletedEventArgs(m_context.SecurityParameters));
        }

        protected UseSrtpData _serverSrtpData;

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);
            
            base.ProcessClientExtensions(clientExtensions);

            UseSrtpData clientSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(clientExtensions);

            // force select SRTP_AES128_CM_HMAC_SHA1_80
            // TODO: review and add support for other profiles
            int[] supportedProfiles = clientSrtpExtension.ProtectionProfiles.Where(x => 
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80 ||
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32
                ).ToArray();
            if(supportedProfiles.Length == 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            _serverSrtpData = new UseSrtpData(supportedProfiles, clientSrtpExtension.Mki);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            var extensions = base.GetServerExtensions();
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _serverSrtpData);
            return extensions;
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;

            // TODO: Review this
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

            if (_myCert == null)
            {
                var cert = DtlsCertificateUtils.GenerateECDSAServerCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
                _myCert = cert.certificate;
                _myCertKey = cert.key;
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _myCertKey, _myCert, signatureAndHashAlgorithm);
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;

            // TODO: Review this
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

            if (_myCert == null)
            {
                (Certificate certificate, AsymmetricKeyParameter key) cert = DtlsCertificateUtils.GenerateRSAServerCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
                _myCert = cert.certificate;
                _myCertKey = cert.key;
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _myCertKey, _myCert, signatureAndHashAlgorithm);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.DTLSv12.Only();
        }
    }
}