using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;

internal class Program
{
    private static void Main(string[] args)
    {
        DtlsClient client = new DtlsClient(null);
        DtlsClientProtocol clientProtocol = new DtlsClientProtocol();

        UdpDatagramTransport clientTransport = new UdpDatagramTransport();
        clientTransport.Connect("127.0.0.1:8888");

        DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.Fill(data, (byte)i);
            dtlsClient.Send(data, 0, data.Length);
        }

        byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
        while (dtlsClient.Receive(buf, 0, buf.Length, 100) >= 0)
        {
        }

        dtlsClient.Close();
    }
}