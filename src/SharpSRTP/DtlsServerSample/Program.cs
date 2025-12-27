using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;
using System.Text;
using System.Threading.Tasks;

DtlsServer server = new DtlsServer();
server.HandshakeCompleted += (sender, e) =>
{
    var keys = SRTPProtocol.GenerateMasterKeys(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, e.SecurityParameters);

    byte[] ck_e = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 16, 0, 0, 0);
    byte[] ck_a = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 20, 1, 0, 0);
    byte[] ck_s = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 14, 2, 0, 0);

    byte[] c_rtcp_k_e = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 16, 3, 0, 0);
    byte[] c_rtcp_k_a = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 20, 4, 0, 0);
    byte[] c_rtcp_k_s = SRTPProtocol.GenerateSessionKey(keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, 14, 5, 0, 0);
    
    byte[] sk_e = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 16, 0, 0, 0);
    byte[] sk_a = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 20, 1, 0, 0);
    byte[] sk_s = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 14, 2, 0, 0);

    byte[] s_rtcp_k_e = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 16, 3, 0, 0);
    byte[] s_rtcp_k_a = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 20, 4, 0, 0);
    byte[] s_rtcp_k_s = SRTPProtocol.GenerateSessionKey(keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, 14, 5, 0, 0);

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
