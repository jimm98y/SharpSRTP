using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;

SrtpKeyGenerator keyGenerator = new SrtpKeyGenerator(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
DtlsClient client = new DtlsClient(null);
client.HandshakeCompleted += (sender, e) =>
{
    keyGenerator.GenerateMasterKeys(e.SecurityParameters);

    int counter = 0;

    byte[] ck_e = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 0, counter);
    byte[] ck_a = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 1, counter);
    byte[] ck_s = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 2, counter);

    byte[] c_rtcp_k_e = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 3, counter);
    byte[] c_rtcp_k_a = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 4, counter);
    byte[] c_rtcp_k_s = keyGenerator.GenerateSessionKey(keyGenerator.ClientWriteMasterKey, keyGenerator.ClientWriteMasterSalt, 5, counter);

    byte[] sk_e = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 0, counter);
    byte[] sk_a = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 1, counter);
    byte[] sk_s = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 2, counter);

    byte[] s_rtcp_k_e = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 3, counter);
    byte[] s_rtcp_k_a = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 4, counter);
    byte[] s_rtcp_k_s = keyGenerator.GenerateSessionKey(keyGenerator.ServerWriteMasterKey, keyGenerator.ServerWriteMasterSalt, 5, counter);

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
