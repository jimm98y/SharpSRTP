using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Threading.Tasks;

bool isShutdown = false;
var ecdsaCertificate = DtlsCertificateUtils.GenerateCertificate("DTLSSRTP", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), false);
var server = new DtlsSrtpServer(ecdsaCertificate.Certificate, ecdsaCertificate.PrivateKey, SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);

UdpDatagramTransport currentClientTransport = null;
server.OnSessionStarted += (sender, e) =>
{
    var context = e.Context;
    var clientTransport = currentClientTransport;
    var session = Task.Run(async () =>
    {
        byte[] rtp = Convert.FromHexString("80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0");
        byte[] rtpBuffer = new byte[context.EncodeRtpContext.CalculateRequiredSrtpPayloadLength(rtp.Length)];
        Buffer.BlockCopy(rtp, 0, rtpBuffer, 0, rtp.Length);
        context.EncodeRtpContext.ProtectRtp(rtpBuffer, rtp.Length, out int length);
        byte[] srtp = rtpBuffer.Take(length).ToArray();
        clientTransport.Send(srtp);
    });
};
UdpDatagramTransport udpServerTransport = new UdpDatagramTransport("127.0.0.1:8888", null); 
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
            currentClientTransport = new UdpDatagramTransport(null, remoteEndpoint);
            return currentClientTransport;
        });
}
