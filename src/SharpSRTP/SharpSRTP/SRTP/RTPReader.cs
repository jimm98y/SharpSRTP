namespace SharpSRTP.SRTP
{
    public static class RTPReader
    {
        public static uint ReadSsrc(byte[] rtpPacket)
        {
            return (uint)((rtpPacket[8] << 24) | (rtpPacket[9] << 16) | (rtpPacket[10] << 8) | rtpPacket[11]);
        }

        public static ushort ReadSequenceNumber(byte[] rtpPacket)
        {
            return (ushort)((rtpPacket[2] << 8) | rtpPacket[3]);
        }

        public static int ReadHeaderLen(byte[] payload)
        {
            int length = 12 + 4 * (payload[0] & 0xf);
            if ((payload[0] & 0x10) == 0x10)
            {
                int extLen = (payload[length + 2] << 8) | payload[length + 3];
                length += 4 + extLen;
            }
            return length;
        }
    }
}
