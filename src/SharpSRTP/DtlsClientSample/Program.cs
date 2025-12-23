using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;

DtlsClient client = new DtlsClient(null);
client.HandshakeCompleted += (sender, e) =>
{
    var keys = SrtpKeyGenerator.GenerateMasterKeys(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, e.SecurityParameters);

    int counter = 0;

    byte[] ck_e = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 0, counter);
    byte[] ck_a = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 1, counter);
    byte[] ck_s = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 2, counter);

    byte[] c_rtcp_k_e = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 3, counter);
    byte[] c_rtcp_k_a = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 4, counter);
    byte[] c_rtcp_k_s = SrtpKeyGenerator.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 5, counter);

    byte[] sk_e = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 0, counter);
    byte[] sk_a = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 1, counter);
    byte[] sk_s = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 2, counter);

    byte[] s_rtcp_k_e = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 3, counter);
    byte[] s_rtcp_k_a = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 4, counter);
    byte[] s_rtcp_k_s = SrtpKeyGenerator.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 5, counter);

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
