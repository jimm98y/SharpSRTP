using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

SrtpKeyGenerator keyGenerator = new SrtpKeyGenerator(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
DtlsServer server = new DtlsServer();
server.HandshakeCompleted += (sender, e) =>
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

DtlsServerProtocol serverProtocol = new DtlsServerProtocol();
UdpDatagramTransport serverTransport = new UdpDatagramTransport("127.0.0.1:8888", null);

bool isShutdown = false;

try
{
    TlsCrypto serverCrypto = server.Crypto;

    // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
    DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

    int receiveLimit = serverTransport.GetReceiveLimit();
    byte[] buf = new byte[serverTransport.GetReceiveLimit()];

    while (!isShutdown)
    {
        DtlsRequest request = null;

        do
        {
            if (isShutdown)
                return;

            int length = serverTransport.Receive(buf, 0, receiveLimit, 100);
            if (length > 0)
            {
                byte[] clientID = Encoding.UTF8.GetBytes(serverTransport.RemoteEndPoint.ToString());
                request = verifier.VerifyRequest(clientID, buf, 0, length, serverTransport);
            }
        }
        while (request == null);

        var clientTransport = new UdpDatagramTransport(null, serverTransport.RemoteEndPoint.ToString());
        var session = Task.Run(() =>
        {
            // NOTE: A real server would handle each DtlsRequest in a new task/thread and continue accepting
            DtlsTransport dtlsTransport = serverProtocol.Accept(server, clientTransport, request);
            byte[] bbuf = new byte[dtlsTransport.GetReceiveLimit()];
            while (!isShutdown)
            {
                int length = dtlsTransport.Receive(bbuf, 0, bbuf.Length, 100);
                if (length >= 0)
                {
                    dtlsTransport.Send(bbuf, 0, length);
                }
            }

            dtlsTransport.Close();
        }
        );
    }
}
catch (Exception e)
{
    Console.Error.WriteLine(e);
    Console.Error.Flush();
}
