using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using SharpSRTP.DTLS;
using SharpSRTP.SRTP;

SrtpKeyGenerator keyGenerator = new SrtpKeyGenerator(Org.BouncyCastle.Tls.SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
DtlsClient client = new DtlsClient(null);
client.HandshakeCompleted += (sender, e) =>
{
    keyGenerator.Generate(e.SecurityParameters);
};

DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
UdpDatagramTransport clientTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");

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
