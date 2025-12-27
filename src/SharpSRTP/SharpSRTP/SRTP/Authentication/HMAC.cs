using Org.BouncyCastle.Crypto.Macs;

namespace SharpSRTP.SRTP.Authentication
{
    public static class HMAC
    {
        public static byte[] GenerateAuthTag(HMac hmac, byte[] payload, int offset, int length)
        {
            hmac.BlockUpdate(payload, offset, length);

            byte[] output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);

            return output;
        }
    }
}
