using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Threading.Tasks;

var ecdsaCertificate = DtlsCertificateUtils.GenerateCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), false);

DtlsServer server = new DtlsServer(ecdsaCertificate.Certificate, ecdsaCertificate.PrivateKey, SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);
server.OnHandshakeCompleted += (sender, e) =>
{
    Console.WriteLine("DTLS Client connected");
};

UdpDatagramTransport udpServerTransport = new UdpDatagramTransport("127.0.0.1:8888", null);
bool isShutdown = false;

try
{
    while (!isShutdown)
    {
        DtlsTransport dtlsTransport = server.DoHandshake(
            out string error,
            udpServerTransport, 
            () =>
            {
                return udpServerTransport.RemoteEndPoint.ToString();
            },
            (remoteEndpoint) =>
            {
                return new UdpDatagramTransport(null, remoteEndpoint);
            });
        
        var remoteEndPoint = udpServerTransport.RemoteEndPoint;
        var session = Task.Run(() =>
        {
            byte[] bbuf = new byte[dtlsTransport.GetReceiveLimit()];
            while (!isShutdown)
            {
                int length = dtlsTransport.Receive(bbuf, 0, bbuf.Length, 100);
                if (length > 0)
                {
                    Console.WriteLine($"Received {bbuf[0]} from {remoteEndPoint.ToString()}");
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
