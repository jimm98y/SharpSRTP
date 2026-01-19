using Org.BouncyCastle.Tls;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.UDP;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

const int RECEIVE_TIMEOUT = 0;
EndPoint localEndpoint = IPEndPointExtensions.Parse("0.0.0.0:8888");
EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
ConcurrentDictionary<string, UdpTransport> activeSessions = new ConcurrentDictionary<string, UdpTransport>();
var server = new DtlsSrtpServer();

Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
listenSocket.ReceiveTimeout = RECEIVE_TIMEOUT;
listenSocket.Bind(localEndpoint);
byte[] buffer = new byte[UdpTransport.MTU];
bool isShutdown = false;

server.OnSessionStarted += (sender, e) =>
{
    var context = e.Context;
    var remoteEndpoint = IPEndPointExtensions.Parse(((UdpTransport)e.Transport).RemoteEndpoint);
    var srtpSession = Task.Run(async () =>
    {
        Console.WriteLine($"SRTP cipher:   {context.EncodeRtpContext.ProtectionProfile.Cipher}, auth: {context.EncodeRtpContext.ProtectionProfile.Auth}");

        ushort sequenceNumber = 1;
        while (!isShutdown)
        {
            byte[] rtpPacket = Convert.FromHexString("80e1000103cb6bc84218a6a3001006c8");
            rtpPacket[2] = (byte)((sequenceNumber >> 8) & 0xff);
            rtpPacket[3] = (byte)(sequenceNumber & 0xff);

            byte[] rtpBuffer = new byte[context.CalculateRequiredSrtpPayloadLength(rtpPacket.Length)];
            Buffer.BlockCopy(rtpPacket, 0, rtpBuffer, 0, rtpPacket.Length);

            Console.WriteLine($"RTP: {Convert.ToHexString(rtpPacket)}");
            if (context.ProtectRtp(rtpBuffer, rtpPacket.Length, out int length) == 0)
            {
                byte[] srtp = rtpBuffer.Take(length).ToArray();
                Console.WriteLine($"SRTP:     {Convert.ToHexString(srtp)}");
                listenSocket.SendTo(srtp, remoteEndpoint);
            }

            sequenceNumber++;
            Thread.Sleep(1000);
        }
    });
};

while (!isShutdown)
{
    int length = 0;
    try
    {
        length = listenSocket.ReceiveFrom(buffer, ref remoteEndpoint);
    }
    catch (SocketException ex)
    {
        Console.WriteLine(ex.Message);
    }

    if (length > 0)
    {
        if (activeSessions.TryGetValue(remoteEndpoint.ToString(), out var transport))
        {
            // current session
            if (!transport.TryAddToReceiveQueue(buffer.ToArray()))
            {
                throw new Exception("Receive queue full!");
            }
        }
        else
        {
            // new session
            UdpTransport udpServerTransport = new UdpTransport(listenSocket, remoteEndpoint, UdpTransport.MTU, (transport) => activeSessions.TryRemove(transport.RemoteEndpoint, out _));
            if (activeSessions.TryAdd(remoteEndpoint.ToString(), udpServerTransport))
            {
                var dtlsSession = Task.Run(() =>
                {
                    DtlsTransport dtlsTransport = server.DoHandshake(udpServerTransport, out string error, null);
                    if (dtlsTransport == null)
                    {
                        Console.WriteLine($"Handshake with {remoteEndpoint} failed with {error}");
                        activeSessions.TryRemove(remoteEndpoint.ToString(), out _);
                    }
                });
            }
        }
    }
}
