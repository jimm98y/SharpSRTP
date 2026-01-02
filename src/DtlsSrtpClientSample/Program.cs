using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Threading.Tasks;

bool isShutdown = false;
var ecdsaCertificate = DtlsCertificateUtils.GenerateCertificate("DTLSSRTP", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), false);
var client = new DtlsSrtpClient(ecdsaCertificate.Certificate, ecdsaCertificate.PrivateKey, SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);
UdpDatagramTransport udpServerTransport = null;
client.OnSessionStarted += (sender, e) =>
{
    var context = e.Context;
    var session = Task.Run(async () =>
    {
        while (!isShutdown)
        {
            byte[] srtp = new byte[2048];
            int receivedLen = udpServerTransport.Receive(srtp, 100);
            if (receivedLen != 0)
            {
                context.DecodeRtpContext.UnprotectRtp(srtp, srtp.Length, out int length);
                byte[] rtp = srtp.Take(length).ToArray();
                Console.WriteLine(Convert.ToHexString(rtp));
                break;
            }
            await Task.Delay(1000);
        }
    });
};
udpServerTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");
DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpServerTransport);

Console.ReadKey();