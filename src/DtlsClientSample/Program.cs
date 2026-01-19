using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

DtlsClient client = new DtlsClient();
Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
IPEndPoint remoteEndpoint = IPEndPointExtensions.Parse("127.0.0.1:8888");
socket.Connect(remoteEndpoint);

UdpTransport udpClientTransport = new UdpTransport(socket);
bool isShutdown = false;

while (!isShutdown)
{
    Console.WriteLine($"Beginning handshake with {remoteEndpoint}");
    DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpClientTransport);
    byte counter = 0;

    if (dtlsTransport != null)
    {
        Console.WriteLine($"DTLS connected");
        while (!isShutdown)
        {
            byte[] data = new byte[] { counter };
            dtlsTransport.Send(data, 0, data.Length);
            counter++;

            byte[] receiveBuffer = new byte[dtlsTransport.GetReceiveLimit()];
            int ret = dtlsTransport.Receive(receiveBuffer, 0, receiveBuffer.Length, 1000);

            if (ret < 0)
            {
                break;
            }

            if (ret > 0)
            {
                Console.WriteLine($"Received {receiveBuffer[0]} from {remoteEndpoint}");
            }

            Thread.Sleep(1000);
        }

        dtlsTransport.Close();
    }
    else
    {
        Console.WriteLine($"Handshake with {remoteEndpoint} failed with {error}");
        Thread.Sleep(1000);
    }
}

socket.Close();