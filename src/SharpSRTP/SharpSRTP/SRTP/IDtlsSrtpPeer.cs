using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;

namespace SharpSRTP.SRTP
{
    public interface IDtlsSrtpPeer : IDtlsPeer
    {
        SrtpSessionContext CreateSessionContext(SecurityParameters securityParameters);
    }
}
