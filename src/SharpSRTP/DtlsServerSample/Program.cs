using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

SrtpKeyGenerator keyGenerator = new SrtpKeyGenerator(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
DtlsServer server = new DtlsServer();
server.HandshakeCompleted += (sender, e) =>
{
    keyGenerator.Generate(e.SecurityParameters);
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
