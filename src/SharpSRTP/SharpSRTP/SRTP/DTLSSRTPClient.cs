using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpSRTP.DTLS;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public class DTLSSRTPClient : DTLSClient
    {
        private readonly SecureRandom _sr;
        protected UseSrtpData _clientSrtpData;

        public int MkiLength { get; protected set; } = 4;

        public DTLSSRTPClient(TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short preferredCertificateAlgorithm = SignatureAlgorithm.rsa) :
           this(new BcTlsCrypto(), session, certificate, privateKey, preferredCertificateAlgorithm)
        { }

        public DTLSSRTPClient(TlsCrypto crypto, TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short preferredCertificateAlgorithm = SignatureAlgorithm.rsa) : 
            base(crypto, session, certificate, privateKey, preferredCertificateAlgorithm)
        {
            int[] protectionProfiles = GetSupportedProtectionProfiles();
            _sr = new SecureRandom();
            byte[] mki = SecureRandom.GetNextBytes(_sr, MkiLength);
            this._clientSrtpData = new UseSrtpData(protectionProfiles, mki);
        }

        protected virtual int[] GetSupportedProtectionProfiles()
        {
            return new int[] 
            {
                //SrtpProtectionProfile.SRTP_AEAD_AES_256_GCM,
                //SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM,

                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32,
                SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80,
                SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32
            };
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            base.ProcessServerExtensions(serverExtensions);

            UseSrtpData serverSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(serverExtensions);

            int[] clientSupportedProfiles = GetSupportedProtectionProfiles();
            int[] supportedProfiles = serverSrtpExtension.ProtectionProfiles.Where(x => clientSupportedProfiles.Contains(x)).ToArray();
            if (supportedProfiles.Length == 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            _clientSrtpData = new UseSrtpData(supportedProfiles, serverSrtpExtension.Mki);
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var extensions = base.GetClientExtensions();

            // add use_srtp extension
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _clientSrtpData);

            return extensions;
        }

        public override TlsAuthentication GetAuthentication()
        {
            if (Certificate == null || CertificatePrivateKey == null)
            {
                (Certificate certificate, AsymmetricKeyParameter key) cert;
                const string webrtcCertificateName = "WebRTC";
                DateTime validFrom = DateTime.UtcNow.AddDays(-1);
                DateTime validTo = DateTime.UtcNow.AddDays(30);

                if (CertificateSignatureAlgorithm == SignatureAlgorithm.ecdsa)
                {
                    cert = DTLSCertificateUtils.GenerateECDSAServerCertificate(webrtcCertificateName, validFrom, validTo);
                }
                else
                {
                    cert = DTLSCertificateUtils.GenerateRSAServerCertificate(webrtcCertificateName, validFrom, validTo);
                }

                SetCertificate(cert.certificate, cert.key, CertificateSignatureAlgorithm);
            }

            return base.GetAuthentication();
        }
    }
}
