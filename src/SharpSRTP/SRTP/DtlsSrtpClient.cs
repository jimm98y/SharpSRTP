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
    public class DtlsSrtpClient : DtlsClient, IDtlsSrtpPeer
    {
        private readonly SecureRandom _rand = new SecureRandom();
        private UseSrtpData _srtpData;
        public UseSrtpData SrtpData { get { return _srtpData; } }
        public SrtpKeys Keys { get; private set; }

        public int MkiLength { get; protected set; } = 4;

        public DtlsSrtpClient(TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) :
           this(new BcTlsCrypto(), session, certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        { }

        public DtlsSrtpClient(TlsCrypto crypto, TlsSession session = null, Certificate certificate = null, AsymmetricKeyParameter privateKey = null, short certificateSignatureAlgorithm = SignatureAlgorithm.rsa, short certificateHashAlgorithm = HashAlgorithm.sha256) : 
            base(crypto, session, certificate, privateKey, certificateSignatureAlgorithm, certificateHashAlgorithm)
        {
            int[] protectionProfiles = GetSupportedProtectionProfiles();
            byte[] mki = GenerateMki(MkiLength);
            this._srtpData = new UseSrtpData(protectionProfiles, mki);
        }

        private byte[] GenerateMki(int length)
        {
            return SecureRandom.GetNextBytes(_rand, length);
        }

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

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            base.ProcessServerExtensions(serverExtensions);

            // https://www.rfc-editor.org/rfc/rfc5764#section-4.1
            UseSrtpData serverSrtpExtension = TlsSrtpUtilities.GetUseSrtpExtension(serverExtensions);

            // verify that the server has selected exactly 1 profile
            int[] clientSupportedProfiles = GetSupportedProtectionProfiles();
            if (serverSrtpExtension.ProtectionProfiles.Length != 1)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            // verify that the server has selected a profile we support
            int selectedProfile = serverSrtpExtension.ProtectionProfiles[0];
            if (!clientSupportedProfiles.Contains(selectedProfile))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            // verify the mki sent by the server matches our mki
            if (_srtpData.Mki != null && serverSrtpExtension.Mki != null && !Enumerable.SequenceEqual(_srtpData.Mki, serverSrtpExtension.Mki))
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            // store the server extension as it contains the selected profile
            _srtpData = serverSrtpExtension;
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var extensions = base.GetClientExtensions();
            TlsSrtpUtilities.AddUseSrtpExtension(extensions, _srtpData);
            return extensions;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            var securityParameters = m_context.SecurityParameters;
            this.Keys = DtlsSrtpProtocol.GenerateMasterKeys(SrtpData.ProtectionProfiles[0], SrtpData.Mki, securityParameters, ForceUseExtendedMasterSecret);
        }

        public virtual SrtpSessionContext CreateSessionContext(SecurityParameters securityParameters)
        {
            // this should only be called from OnHandshakeCompleted so we should still have _srtpData from the connection
            if (m_context == null)
                throw new InvalidOperationException();

            SrtpKeys keys = DtlsSrtpProtocol.GenerateMasterKeys(_srtpData.ProtectionProfiles[0], _srtpData.Mki, securityParameters, ForceUseExtendedMasterSecret);
            var encodeRtpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTP);
            var encodeRtcpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTCP);
            var decodeRtpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTP);
            var decodeRtcpContext = new SrtpContext(keys.ProtectionProfile, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTCP);
            return new SrtpSessionContext(encodeRtpContext, decodeRtpContext, encodeRtcpContext, decodeRtcpContext);
        }
    }
}
