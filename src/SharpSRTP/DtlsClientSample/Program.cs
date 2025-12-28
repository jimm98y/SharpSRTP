using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;

DTLSSRTPClient client = new DTLSSRTPClient();
client.HandshakeCompleted += (sender, e) =>
{
    var keys = SRTProtocol.GenerateMasterKeys(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, e.SecurityParameters);

    var ck = new SRTPContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SRTPContextType.RTP);
    var c_rtcp = new SRTPContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SRTPContextType.RTCP);

    var sk = new SRTPContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SRTPContextType.RTP);
    var s_rtcp = new SRTPContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SRTPContextType.RTCP);

    Console.WriteLine("Client RTP k_e:  " + Convert.ToHexString(ck.K_e));
    Console.WriteLine("Client RTP k_a:  " + Convert.ToHexString(ck.K_a));
    Console.WriteLine("Client RTP k_s:  " + Convert.ToHexString(ck.K_s));

    Console.WriteLine("Client RTCP k_e: " + Convert.ToHexString(c_rtcp.K_e));
    Console.WriteLine("Client RTCP k_a: " + Convert.ToHexString(c_rtcp.K_a));
    Console.WriteLine("Client RTCP k_s: " + Convert.ToHexString(c_rtcp.K_s));

    Console.WriteLine("Server RTP k_e:  " + Convert.ToHexString(sk.K_e));
    Console.WriteLine("Server RTP k_a:  " + Convert.ToHexString(sk.K_a));
    Console.WriteLine("Server RTP k_s:  " + Convert.ToHexString(sk.K_s));

    Console.WriteLine("Server RTCP k_e: " + Convert.ToHexString(s_rtcp.K_e));
    Console.WriteLine("Server RTCP k_a: " + Convert.ToHexString(s_rtcp.K_a));
    Console.WriteLine("Server RTCP k_s: " + Convert.ToHexString(s_rtcp.K_s));
};

DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
UdpDatagramTransport clientTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");

DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

for (int i = 1; i <= 10; ++i)
{
    byte[] data = new byte[i];
    Arrays.Fill(data, (byte)i);
    dtlsClient.Send(data, 0, data.Length);
}

byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
while (dtlsClient.Receive(buf, 0, buf.Length, 100) >= 0)
{
}

dtlsClient.Close();
