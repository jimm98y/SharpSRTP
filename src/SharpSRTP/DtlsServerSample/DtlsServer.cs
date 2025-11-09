using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;

namespace SharpSRTP.DTLS
{
    public class DtlsServer : DefaultTlsServer
    {
        internal DtlsServer() : this(new BcTlsCrypto())
        {
        }

        internal DtlsServer(TlsCrypto crypto) : base(crypto)
        {
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS server raised alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
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
            short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
                ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(m_context.ServerVersion))
            {
                serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
            }

            var certificateAuthorities = new List<X509Name>();

            // All the CA certificates are currently configured with this subject
            certificateAuthorities.Add(new X509Name("CN=BouncyCastle TLS Test CA"));

            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            TlsCertificate[] chain = clientCertificate.GetCertificateList();

            Console.WriteLine("DTLS server received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                Console.WriteLine("    fingerprint:SHA-256 " + CertificateUtils.Fingerprint(entry) + " ("
                    + entry.Subject + ")");
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

            TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0],
                trustedCertResources);

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

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            //return TlsTestUtilities.LoadEncryptionCredentials(m_context,
            //    new string[] { "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" }, "x509-server-key-rsa-enc.pem");
            return base.GetRsaEncryptionCredentials();
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;

            //return TlsTestUtilities.LoadSignerCredentialsServer(m_context, clientSigAlgs, SignatureAlgorithm.rsa);

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

            var clientCertificate = CertificateUtils.GenerateServerCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
            Certificate certificate = null;
            AsymmetricKeyParameter privateKey = null;
            using (var pem = new PemReader(new StringReader(clientCertificate.certificate)))
            {
                var pemCertificate = pem.ReadPemObject();
                if (pemCertificate.Type.EndsWith("CERTIFICATE"))
                {
                    var tlsCertificate = m_context.Crypto.CreateCertificate(pemCertificate.Content);
                    certificate = new Certificate(new TlsCertificate[] { tlsCertificate });
                }
            }
            using (var pem = new PemReader(new StringReader(clientCertificate.key)))
            {
                var pemPrivateKey = pem.ReadPemObject();
                if (pemPrivateKey.Type.EndsWith("PRIVATE KEY"))
                {
                    if (pemPrivateKey.Type.Equals("PRIVATE KEY"))
                    {
                        privateKey = PrivateKeyFactory.CreateKey(pemPrivateKey.Content);
                    }
                    if (pemPrivateKey.Type.Equals("ENCRYPTED PRIVATE KEY"))
                    {
                        throw new NotSupportedException("Encrypted PKCS#8 keys not supported");
                    }
                    if (pemPrivateKey.Type.Equals("RSA PRIVATE KEY"))
                    {
                        RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(pemPrivateKey.Content);
                        privateKey = new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                            rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                            rsa.Exponent2, rsa.Coefficient);
                    }
                    if (pemPrivateKey.Type.Equals("EC PRIVATE KEY"))
                    {
                        ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(pemPrivateKey.Content);
                        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.Parameters);
                        PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
                        privateKey = PrivateKeyFactory.CreateKey(privInfo);
                    }
                }
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, privateKey, certificate, signatureAndHashAlgorithm);
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