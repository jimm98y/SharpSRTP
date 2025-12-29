namespace SharpSRTP.SRTP
{
    public class SrtpSessionContext
    {
        public SrtpContext EncodeRtpContext { get; private set; }
        public SrtpContext EncodeRtcpContext { get; private set; }
        public SrtpContext DecodeRtpContext { get; private set; }
        public SrtpContext DecodeRtcpContext { get; private set; }

        public SrtpSessionContext(SrtpContext encodeRtpContext, SrtpContext decodeRtpContext, SrtpContext encodeRtcpContext, SrtpContext decodeRtcpContext)
        {
            this.EncodeRtpContext = encodeRtpContext;
            this.DecodeRtpContext = decodeRtpContext;
            this.EncodeRtcpContext = encodeRtcpContext;
            this.DecodeRtcpContext = decodeRtcpContext;
        }
    }
}
