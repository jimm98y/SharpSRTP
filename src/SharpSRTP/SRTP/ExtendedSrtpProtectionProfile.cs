using Org.BouncyCastle.Tls;

namespace SharpSRTP.SRTP
{
    /// <summary>
    /// Currently registered DTLS-SRTP profiles: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1
    /// </summary>
    public abstract class ExtendedSrtpProtectionProfile : SrtpProtectionProfile
    {
        // TODO: Remove this once BouncyCastle adds the constants
        public const int DRAFT_SRTP_AES256_CM_SHA1_80 = 0x0003;
        public const int DRAFT_SRTP_AES256_CM_SHA1_32 = 0x0004;
        public const int DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 0x0009;
        public const int DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = 0x000A;
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_80 = 0x000B;
        public const int SRTP_ARIA_128_CTR_HMAC_SHA1_32 = 0x000C;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_80 = 0x000D;
        public const int SRTP_ARIA_256_CTR_HMAC_SHA1_32 = 0x000E;
        public const int SRTP_AEAD_ARIA_128_GCM = 0x000F;
        public const int SRTP_AEAD_ARIA_256_GCM = 0x0010;
    }
}
