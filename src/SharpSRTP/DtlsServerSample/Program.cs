using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;
using System.Text;
using System.Threading.Tasks;

DtlsSrtpServer server = new DtlsSrtpServer();
server.HandshakeCompleted += (sender, e) =>
{
    var keys = DtlsSrtpProtocol.GenerateMasterKeys(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, server.SrtpData.Mki, e.SecurityParameters);

    var ck = new SrtpContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTP);
    var c_rtcp = new SrtpContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.Mki, keys.ClientWriteMasterKey, keys.ClientWriteMasterSalt, SrtpContextType.RTCP);

    var sk = new SrtpContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTP);
    var s_rtcp = new SrtpContext(Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, keys.Mki, keys.ServerWriteMasterKey, keys.ServerWriteMasterSalt, SrtpContextType.RTCP);

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
