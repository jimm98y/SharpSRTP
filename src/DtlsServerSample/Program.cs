using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

var ecdsaCertificate = DtlsCertificateUtils.GenerateCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), false);

object serverLock = new object();
DtlsServer server = new DtlsServer(ecdsaCertificate.Certificate, ecdsaCertificate.PrivateKey, SignatureAlgorithm.ecdsa, HashAlgorithm.sha256);
server.OnHandshakeCompleted += (sender, e) =>
{
    Console.WriteLine("DTLS Client connected");
};

TlsCrypto serverCrypto = new BcTlsCrypto();
DtlsVerifier verifier = new DtlsVerifier(serverCrypto);
DtlsRequest request = null;
Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
int receiveLimit = UdpTransport.MTU;
byte[] buf = new byte[receiveLimit];
bool isShutdown = false;

try
{
    IPEndPoint local = IPEndPointExtensions.Parse("0.0.0.0:8888");
    listenSocket.Bind(local);
    Console.WriteLine($"Server is listening on {local}");
    ConcurrentDictionary<string, UdpTransport> sessions = new ConcurrentDictionary<string, UdpTransport>();
    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

    while (!isShutdown)
    {
        int length = 0;
        try
        {
            length = listenSocket.ReceiveFrom(buf, ref remote);
        }
        catch(SocketException ex)
        {
            System.Diagnostics.Debug.WriteLine(ex.Message);
        }

        if (length > 0)
        {
            if (sessions.TryGetValue(remote.ToString(), out var transport))
            {
                // current session
                transport.TryAddToReceiveQueue(buf.ToArray());
            }
            else
            {
                // new session
                var clientID = remote.Serialize().Buffer.ToArray();
                request = verifier.VerifyRequest(clientID, buf, 0, length, new UdpSender(listenSocket, remote, UdpTransport.MTU));

                if (request != null)
                {
                    UdpTransport udpServerTransport = new UdpTransport(listenSocket, remote, (transport) => sessions.TryRemove(transport.RemoteEndpoint, out _));
                    if (sessions.TryAdd(remote.ToString(), udpServerTransport))
                    {
                        var session = Task.Run(() =>
                        {
                            DtlsTransport dtlsTransport = null;
                            lock (serverLock)
                            {
                                dtlsTransport = server.DoHandshake(out string error, udpServerTransport, request);
                            }
                            if (dtlsTransport != null)
                            {
                                byte[] bbuf = new byte[dtlsTransport.GetReceiveLimit()];
                                while (!isShutdown)
                                {
                                    int length = dtlsTransport.Receive(bbuf, 0, bbuf.Length, 100);
                                    if (length > 0)
                                    {
                                        Console.WriteLine($"Received {bbuf[0]} from {remote.ToString()}");
                                        dtlsTransport.Send(bbuf, 0, length);
                                    }
                                }

                                dtlsTransport.Close();
                            }
                        });
                    }
                }
            }
        }
    }
}
catch (Exception e)
{
    Console.Error.WriteLine(e);
    Console.Error.Flush();
}
