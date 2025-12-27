namespace SharpSRTP.SRTP
{
    public static class RTCPReader
    {
        public static int GetHeaderLen()
        {
            return 8;
        }

        public static uint ReadSsrc(byte[] rtcpPacket)
        {
            return (uint)((rtcpPacket[4] << 24) | (rtcpPacket[5] << 16) | (rtcpPacket[6] << 8) | rtcpPacket[7]);
        }

        public static uint SRTCPReadIndex(byte[] srtcpPacket, int authTagLen)
        {
            int index = srtcpPacket.Length - authTagLen - 4;
            return (uint)((srtcpPacket[index] << 24) | (srtcpPacket[index + 1] << 16) | (srtcpPacket[index + 2] << 8) | srtcpPacket[index + 3]);
        }
    }
}
