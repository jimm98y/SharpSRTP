using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpSRTP.DTLS
{
    public class DtlsClient : DefaultTlsClient
    {
        protected Certificate _myCert;
        protected AsymmetricKeyParameter _myCertKey;
        protected UseSrtpData _clientSrtpData;

        public TlsServerCertificate ServerCertificate { get; private set; }

        public event EventHandler<DtlsHandshakeCompletedEventArgs> HandshakeCompleted;

        private TlsSession m_session;
        private readonly SecureRandom m_sr;
        private int m_handshakeTimeoutMillis = 0;

        public DtlsClient(TlsSession session = null) : this(new BcTlsCrypto(), session)
        { }

        public DtlsClient(TlsCrypto crypto, TlsSession session = null) : base(crypto)
        {
            this.m_session = session;

            // list of all supported profiles
            int[] protectionProfiles = { 
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32,
                SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80,
                SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32
            };

            m_sr = new SecureRandom();
            byte[] mki = SecureRandom.GetNextBytes(m_sr, 4);
            this._clientSrtpData = new UseSrtpData(protectionProfiles, mki);
        }

        public override TlsSession GetSessionToResume()
        {
            return this.m_session;
        }

        public override int GetHandshakeTimeoutMillis() => m_handshakeTimeoutMillis;

        public void SetHandshakeTimeoutMillis(int millis) => m_handshakeTimeoutMillis = millis;

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS client raised alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
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
            output.WriteLine("DTLS client received alert: " + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            Console.WriteLine("DTLS client negotiated " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            if (_myCert == null)
            {
                (Certificate certificate, AsymmetricKeyParameter key) cert = DtlsCertificateUtils.GenerateRSAServerCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
                _myCert = cert.certificate;
                _myCertKey = cert.key;
            }

            return new MyTlsAuthentication(m_context, this);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Client ALPN: " + protocolName.GetUtf8Decoding());
            }

            TlsSession newSession = m_context.Session;
            if (newSession != null)
            {
                if (newSession.IsResumable)
                {
                    byte[] newSessionID = newSession.SessionID;
                    string hex = ToHexString(newSessionID);

                    if (m_session != null && Arrays.AreEqual(m_session.SessionID, newSessionID))
                    {
                        Console.WriteLine("Client resumed session: " + hex);
                    }
                    else
                    {
                        Console.WriteLine("Client established session: " + hex);
                    }

                    this.m_session = newSession;
                }

                byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
                if (null != tlsServerEndPoint)
                {
                    Console.WriteLine("Client 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));
                }

                byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
                Console.WriteLine("Client 'tls-unique': " + ToHexString(tlsUnique));
            }

            HandshakeCompleted?.Invoke(this, new DtlsHandshakeCompletedEventArgs(m_context.SecurityParameters));
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            var extensions = base.GetClientExtensions();
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _clientSrtpData);
            return extensions;
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);

            UseSrtpData serverSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(serverExtensions);

            // TODO: review and add support for other profiles
            int[] supportedProfiles = serverSrtpExtension.ProtectionProfiles.Where(x =>
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80 ||
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32 ||
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80 ||
                x == Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32
                ).ToArray();
            if (supportedProfiles.Length == 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            _clientSrtpData = new UseSrtpData(supportedProfiles, serverSrtpExtension.Mki);
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
            private readonly DtlsClient m_client;

            public MyTlsAuthentication(TlsContext context, DtlsClient client)
            {
                this.m_client = client ?? throw new ArgumentNullException(nameof(client));
                this.m_context = context;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();

                Console.WriteLine("DTLS client received server certificate chain of length " + chain.Length);
                for (int i = 0; i != chain.Length; i++)
                {
                    X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    Console.WriteLine("    fingerprint:SHA-256 " + DtlsCertificateUtils.Fingerprint(entry) + " (" + entry.Subject + ")");
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
                    return null;

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

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, m_client._myCertKey, m_client._myCert, signatureAndHashAlgorithm);
            }
        }
    }
}