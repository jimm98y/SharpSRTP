using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpSRTP.DTLS;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public class DtlsSrtpServer : DtlsServer, IDtlsSrtpPeer
    {
        private UseSrtpData _srtpData;
        public UseSrtpData SrtpData { get { return _srtpData; } }
        public SrtpKeys Keys { get; private set; } 

        public DtlsSrtpServer(Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) 
            : this(new BcTlsCrypto(), certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        public DtlsSrtpServer(TlsCrypto crypto, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) 
            : base(crypto, certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        protected virtual int[] GetSupportedProtectionProfiles()
        {
            return new int[] 
            {
                ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_256_GCM,
                ExtendedSrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_32,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_32,

                ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_256_GCM,
                ExtendedSrtpProtectionProfile.SRTP_AEAD_AES_128_GCM,

                ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32,

                ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80,
                ExtendedSrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32
            };
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            base.ProcessClientExtensions(clientExtensions);

            UseSrtpData clientSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(clientExtensions);

            int[] serverSupportedProfiles = GetSupportedProtectionProfiles();
            int[] mutuallySupportedProfiles = clientSrtpExtension.ProtectionProfiles.Where(x => serverSupportedProfiles.Contains(x)).ToArray();
            if (mutuallySupportedProfiles.Length == 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            int selectedProfile = mutuallySupportedProfiles.OrderBy(x => Array.IndexOf(serverSupportedProfiles, x)).First(); // Choose the highest priority profile supported by the server
            _srtpData = new UseSrtpData(new int[] { selectedProfile }, clientSrtpExtension.Mki); // Server must return only a single selected profile
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            var extensions = base.GetServerExtensions();
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _srtpData);
            return extensions;
        }

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            if (Certificate == null)
            {
                const string webrtcCertificateName = "WebRTC";
                DateTime validFrom = DateTime.UtcNow.AddDays(-1);
                DateTime validTo = DateTime.UtcNow.AddDays(30);

                var cert = DtlsCertificateUtils.GenerateECDSAServerCertificate(webrtcCertificateName, validFrom, validTo);
                SetCertificate(cert.certificate, cert.key, SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);
            }

            return base.GetECDsaSignerCredentials();
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            if (Certificate == null || CertificatePrivateKey == null)
            {
                const string webrtcCertificateName = "WebRTC";
                DateTime validFrom = DateTime.UtcNow.AddDays(-1);
                DateTime validTo = DateTime.UtcNow.AddDays(30);

                var cert = DtlsCertificateUtils.GenerateRSAServerCertificate(webrtcCertificateName, validFrom, validTo);
                SetCertificate(cert.certificate, cert.key, SignatureAlgorithm.rsa, HashAlgorithm.sha256);
            }

            return base.GetRsaSignerCredentials();
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            var securityParameters = m_context.SecurityParameters;
            this.Keys = DtlsSrtpProtocol.GenerateMasterKeys(SrtpData.ProtectionProfiles[0], SrtpData.Mki, securityParameters, ForceUseExtendedMasterSecret);
        }
    }
}
