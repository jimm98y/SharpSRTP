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
        byte[] rtp = Convert.FromHexString("80e1000103cb6bc84218a6a3001006c8");
        byte[] rtpBuffer = new byte[context.EncodeRtpContext.CalculateRequiredSrtpPayloadLength(rtp.Length)];
        Buffer.BlockCopy(rtp, 0, rtpBuffer, 0, rtp.Length);

        Console.WriteLine($"Encrypting RTP: {Convert.ToHexString(rtp)}");
        context.EncodeRtpContext.ProtectRtp(rtpBuffer, rtp.Length, out int length);
        byte[] srtp = rtpBuffer.Take(length).ToArray();

        Console.WriteLine($"Sending SRTP: {Convert.ToHexString(srtp)}");
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
