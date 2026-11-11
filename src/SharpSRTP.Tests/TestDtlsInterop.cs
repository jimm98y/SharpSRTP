using SharpSRTP.DTLS;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using SharpSRTP.UDP;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SharpSRTP.Tests
{
    /// <summary>
    /// The SharpDTLS peers (the default) and the BouncyCastle ones, against each other and themselves, over loopback UDP.
    /// On net481 this runs SharpDTLS's netstandard2.0 build.
    /// </summary>
    [TestClass]
    public sealed class TestDtlsInterop
    {
        private const int Dtls12 = 0xFEFD;
        private const int Dtls13 = 0xFEFC;
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

        [DataRow(false, false, Dtls13)]
        [DataRow(false, true, Dtls12)]
        [DataRow(true, false, Dtls12)]
        [DataRow(true, true, Dtls12)]
        [TestMethod]
        public void Dtls_HandshakeAndEcho(bool bouncyCastleClient, bool bouncyCastleServer, int expectedVersion)
        {
            IDtlsPeer client = bouncyCastleClient ? new BcDtlsClient() : new DtlsClient();
            IDtlsServerPeer server = bouncyCastleServer ? new BcDtlsServer() : new DtlsServer();
            int clientVersion = 0, serverVersion = 0;
            client.OnHandshakeCompleted += (_, e) => clientVersion = e.SecurityParameters.NegotiatedVersion;
            server.OnHandshakeCompleted += (_, e) => serverVersion = e.SecurityParameters.NegotiatedVersion;

            var (clientSocket, serverSocket) = ConnectedPair();
            using (clientSocket)
            using (serverSocket)
            {
                var (clientTransport, serverTransport) = Handshake(client, server, clientSocket, serverSocket);
                Assert.AreEqual(expectedVersion, clientVersion, "client version");
                Assert.AreEqual(expectedVersion, serverVersion, "server version");

                Send(clientTransport, "ping");
                Assert.AreEqual("ping", ReceiveText(serverTransport));
                Send(serverTransport, "pong");
                Assert.AreEqual("pong", ReceiveText(clientTransport));
            }
        }

        [DataRow(false, false)]
        [DataRow(false, true)]
        [DataRow(true, false)]
        [DataRow(true, true)]
        [TestMethod]
        public void DtlsSrtp_BothSidesDeriveTheSameKeys(bool bouncyCastleClient, bool bouncyCastleServer)
        {
            IDtlsSrtpPeer client = bouncyCastleClient ? new BcDtlsSrtpClient() : new DtlsSrtpClient();
            IDtlsSrtpPeer server = bouncyCastleServer ? new BcDtlsSrtpServer() : new DtlsSrtpServer();
            SrtpSessionContext clientContext = null, serverContext = null;
            client.OnSessionStarted += (_, e) => clientContext = e.Context;
            server.OnSessionStarted += (_, e) => serverContext = e.Context;

            var (clientSocket, serverSocket) = ConnectedPair();
            using (clientSocket)
            using (serverSocket)
            {
                Handshake(client, (IDtlsServerPeer)server, clientSocket, serverSocket);
                Assert.IsNotNull(clientContext, "client session");
                Assert.IsNotNull(serverContext, "server session");

                byte[] rtp = HexToBytes("80e1000103cb6bc84218a6a3001006c8");
                byte[] buffer = new byte[serverContext.CalculateRequiredSrtpPayloadLength(rtp.Length)];
                Buffer.BlockCopy(rtp, 0, buffer, 0, rtp.Length);
                Assert.AreEqual(0, serverContext.ProtectRtp(buffer, rtp.Length, out int protectedLength));
                Assert.AreEqual(0, clientContext.UnprotectRtp(buffer, protectedLength, out int length));
                CollectionAssert.AreEqual(rtp, buffer.Take(length).ToArray());
            }
        }

        private static (IDtlsTransport Client, IDtlsTransport Server) Handshake(IDtlsPeer client, IDtlsServerPeer server, Socket clientSocket, Socket serverSocket)
        {
            string serverError = null;
            var serverHandshake = Task.Run(() => server.DoHandshake(out serverError, new UdpTransport(serverSocket)));
            var clientTransport = client.DoHandshake(out string clientError, new UdpTransport(clientSocket));
            Assert.IsTrue(serverHandshake.Wait(Timeout), "server handshake timed out");
            Assert.IsNotNull(clientTransport, "client: " + clientError);
            Assert.IsNotNull(serverHandshake.Result, "server: " + serverError);
            return (clientTransport, serverHandshake.Result);
        }

        private static (Socket Client, Socket Server) ConnectedPair()
        {
            var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            server.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            client.Connect(server.LocalEndPoint);
            server.Connect(client.LocalEndPoint);
            return (client, server);
        }

        private static void Send(IDtlsTransport transport, string text)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            transport.Send(data, 0, data.Length);
        }

        private static string ReceiveText(IDtlsTransport transport)
        {
            byte[] buffer = new byte[transport.GetReceiveLimit()];
            int length = transport.Receive(buffer, 0, buffer.Length, (int)Timeout.TotalMilliseconds);
            Assert.IsGreaterThan(0, length, "nothing received");
            return Encoding.UTF8.GetString(buffer, 0, length);
        }

        private static byte[] HexToBytes(string hex)
            => Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(2 * i, 2), 16)).ToArray();
    }
}
