using SharpSRTP.DTLS;

namespace SharpSRTP.SRTP
{
    public interface IDtlsSrtpPeer : IDtlsPeer
    {
        SrtpKeys Keys { get; }
    }
}
