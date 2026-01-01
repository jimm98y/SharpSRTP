using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Text;
using System.Threading.Tasks;

var rsaCertificate = DtlsCertificateUtils.GenerateCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), true);

DtlsServer server = new DtlsServer(rsaCertificate.certificate, rsaCertificate.key, SignatureAlgorithm.rsa, HashAlgorithm.sha256);
server.OnHandshakeCompleted += (sender, e) =>
{
    Console.WriteLine("DTLS Client connected");
};

DtlsServerProtocol serverProtocol = new DtlsServerProtocol();
UdpDatagramTransport udpServerTransport = new UdpDatagramTransport("127.0.0.1:8888", null);

bool isShutdown = false;

try
{
    TlsCrypto serverCrypto = server.Crypto;

    // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
    DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

    int receiveLimit = udpServerTransport.GetReceiveLimit();
    byte[] buf = new byte[receiveLimit];

    while (!isShutdown)
    {
        DtlsRequest request = null;

        do
        {
            if (isShutdown)
                return;

            int length = udpServerTransport.Receive(buf, 0, receiveLimit, 100);
            if (length > 0)
            {
                byte[] clientID = Encoding.UTF8.GetBytes(udpServerTransport.RemoteEndPoint.ToString());
                request = verifier.VerifyRequest(clientID, buf, 0, length, udpServerTransport);
            }
        }
        while (request == null);

        var clientTransport = new UdpDatagramTransport(null, udpServerTransport.RemoteEndPoint.ToString());
        var session = Task.Run(() =>
        {
            DtlsTransport dtlsTransport = serverProtocol.Accept(server, clientTransport, request);
            byte[] bbuf = new byte[dtlsTransport.GetReceiveLimit()];
            while (!isShutdown)
            {
                int length = dtlsTransport.Receive(bbuf, 0, bbuf.Length, 100);
                if (length > 0)
                {
                    Console.WriteLine($"Received {bbuf[0]} from {clientTransport.RemoteEndPoint.ToString()}");
                    dtlsTransport.Send(bbuf, 0, length);
                }
            }

            dtlsTransport.Close();
        });
    }
}
catch (Exception e)
{
    Console.Error.WriteLine(e);
    Console.Error.Flush();
}
