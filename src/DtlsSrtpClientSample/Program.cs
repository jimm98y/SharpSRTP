using Org.BouncyCastle.Tls;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

bool isShutdown = false;
bool isSrtpSessionRunning = false;
var client = new DtlsSrtpClient();
Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
IPEndPoint remoteEndpoint = IPEndPointExtensions.Parse("127.0.0.1:8888");
socket.Connect(remoteEndpoint);

UdpTransport udpClientTransport = new UdpTransport(socket, null, UdpTransport.MTU);
client.OnSessionStarted += (sender, e) =>
{
    isSrtpSessionRunning = true;
    socket.ReceiveTimeout = 1000; 

    var context = e.Context;
    var srtpSession = Task.Run(async () =>
    {
        var protectionProfile = context.DecodeRtpContext.ProtectionProfile;
        Console.WriteLine($"SRTP cipher:   {protectionProfile.Cipher}, auth: {protectionProfile.Auth}");
        
        byte[] receiveBuffer = new byte[2048];
        int timeoutCounter = 0;

        while (!isShutdown)
        {
            int receivedLen = 0;            
            try
            {
                receivedLen = socket.Receive(receiveBuffer);
                timeoutCounter = 0;
            }
            catch (SocketException ex)
            {
                if(ex.SocketErrorCode == SocketError.TimedOut)
                {
                    timeoutCounter++;
                }
            }
                
            if (receivedLen != 0)
            {
                Console.WriteLine($"SRTP: {Convert.ToHexString(receiveBuffer.Take(receivedLen).ToArray())}");

                if (context.UnprotectRtp(receiveBuffer, receivedLen, out int length) == 0)
                {
                    byte[] rtp = receiveBuffer.Take(length).ToArray();
                    Console.WriteLine($"RTP: {Convert.ToHexString(rtp)}");
                }
            }

            if(timeoutCounter > 30)
            {
                isSrtpSessionRunning = false;
                break;
            }
        }
    });
};

while (!isShutdown)
{
    Console.WriteLine($"Beginning handshake with {remoteEndpoint}");
    DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpClientTransport);
    if (dtlsTransport != null)
    {
        Console.WriteLine($"DTLS connected");

        while(isSrtpSessionRunning)
        {
            Thread.Sleep(1000);
        }
    }
    else
    {
        Console.WriteLine($"Handshake with {remoteEndpoint} failed with {error}");
        Thread.Sleep(1000);
    }
}
