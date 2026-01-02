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

UdpDatagramTransport udpClientTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");
DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpClientTransport);

byte counter = 0;

while (true)
{
    byte[] data = new byte[] { counter };
    dtlsTransport.Send(data, 0, data.Length);
    counter++;

    byte[] buf = new byte[dtlsTransport.GetReceiveLimit()];
    int ret = dtlsTransport.Receive(buf, 0, buf.Length, 100);
    if (ret < 0) break;
    if (ret > 0)
    {
        Console.WriteLine($"Received {buf[0]}");
    }

    Thread.Sleep(1000);
}

dtlsTransport.Close();
