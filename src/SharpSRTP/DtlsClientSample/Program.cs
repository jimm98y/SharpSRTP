using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;

DtlsClient client = new DtlsClient(null);
client.HandshakeCompleted += (sender, e) =>
{
    var keys = SrtpKeyGenerator.GenerateMasterKeys(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, e.SecurityParameters);

    byte[] ck_e = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 16, 0, 0, 0);
    byte[] ck_a = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 20, 1, 0, 0);
    byte[] ck_s = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 14, 2, 0, 0);

    byte[] c_rtcp_k_e = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 16, 3, 0, 0);
    byte[] c_rtcp_k_a = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 20, 4, 0, 0);
    byte[] c_rtcp_k_s = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 14, 5, 0, 0);

    byte[] sk_e = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 16, 0, 0, 0);
    byte[] sk_a = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 20, 1, 0, 0);
    byte[] sk_s = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 14, 2, 0, 0);

    byte[] s_rtcp_k_e = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 16, 3, 0, 0);
    byte[] s_rtcp_k_a = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 20, 4, 0, 0);
    byte[] s_rtcp_k_s = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 14, 5, 0, 0);

    Console.WriteLine("Client RTP k_e:  " + Convert.ToHexString(ck_e));
    Console.WriteLine("Client RTP k_a:  " + Convert.ToHexString(ck_a));
    Console.WriteLine("Client RTP k_s:  " + Convert.ToHexString(ck_s));

    Console.WriteLine("Client RTCP k_e: " + Convert.ToHexString(c_rtcp_k_e));
    Console.WriteLine("Client RTCP k_a: " + Convert.ToHexString(c_rtcp_k_a));
    Console.WriteLine("Client RTCP k_s: " + Convert.ToHexString(c_rtcp_k_s));

    Console.WriteLine("Server RTP k_e:  " + Convert.ToHexString(sk_e));
    Console.WriteLine("Server RTP k_a:  " + Convert.ToHexString(sk_a));
    Console.WriteLine("Server RTP k_s:  " + Convert.ToHexString(sk_s));

    Console.WriteLine("Server RTCP k_e: " + Convert.ToHexString(s_rtcp_k_e));
    Console.WriteLine("Server RTCP k_a: " + Convert.ToHexString(s_rtcp_k_a));
    Console.WriteLine("Server RTCP k_s: " + Convert.ToHexString(s_rtcp_k_s));
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
