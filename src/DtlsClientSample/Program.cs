using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Threading;

DtlsClient client = new DtlsClient();
client.OnHandshakeCompleted += (sender, e) =>
{
    Console.WriteLine("DTLS client connected");
};

DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
UdpDatagramTransport udpClientTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");
DtlsTransport dtlsClientTransport = clientProtocol.Connect(client, udpClientTransport);

byte counter = 0;

while (true)
{
    byte[] data = new byte[] { counter };
    dtlsClientTransport.Send(data, 0, data.Length);
    counter++;

    byte[] buf = new byte[dtlsClientTransport.GetReceiveLimit()];
    int ret = dtlsClientTransport.Receive(buf, 0, buf.Length, 100);
    if (ret < 0) break;
    if (ret > 0)
    {
        Console.WriteLine($"Received {buf[0]}");
    }

    Thread.Sleep(1000);
}

dtlsClientTransport.Close();
