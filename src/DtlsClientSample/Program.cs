using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Net.Sockets;
using System.Threading;

DtlsClient client = new DtlsClient();
client.OnHandshakeCompleted += (sender, e) =>
{
    Console.WriteLine("DTLS client connected");
};

Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
var remote = IPEndPointExtensions.Parse("127.0.0.1:8888");
socket.Connect(remote);

UdpTransport udpClientTransport = new UdpTransport(socket);
bool isRunning = true;

while (isRunning)
{
    Console.WriteLine($"Connecting to {remote}");
    DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpClientTransport);
    byte counter = 0;

    if (dtlsTransport != null)
    {
        Console.WriteLine($"Connected");
        while (isRunning)
        {
            byte[] data = new byte[] { counter };
            dtlsTransport.Send(data, 0, data.Length);
            counter++;

            byte[] buf = new byte[dtlsTransport.GetReceiveLimit()];
            int ret = dtlsTransport.Receive(buf, 0, buf.Length, 1000);
            
            if (ret < 0) 
                break;

            if (ret > 0)
            {
                Console.WriteLine($"Received {buf[0]}");
            }

            Thread.Sleep(1000);
        }
        dtlsTransport.Close();
    }
    else
    {
        Thread.Sleep(1000);
    }
}