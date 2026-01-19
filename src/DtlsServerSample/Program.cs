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
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

const int RECEIVE_TIMEOUT = 0;
const int INACTIVE_SESSION_TIMEOUT = 60000;
EndPoint localEndpoint = IPEndPointExtensions.Parse("0.0.0.0:8888");
EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
ConcurrentDictionary<string, UdpTransport> activeSessions = new ConcurrentDictionary<string, UdpTransport>();
DtlsServer server = new DtlsServer();
TlsCrypto serverCrypto = new BcTlsCrypto();
DtlsVerifier verifier = new DtlsVerifier(serverCrypto);
Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
listenSocket.ReceiveTimeout = RECEIVE_TIMEOUT;

if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    // disables the SocketException on client hard crash
    const int SIO_UDP_CONNRESET = -1744830452;
    listenSocket.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
    listenSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
}

byte[] buffer = new byte[UdpTransport.MTU];
bool isShutdown = false;
bool isHelloVerifyEnabled = true;

Timer sessionCleanup = new Timer((o) =>
{
    UdpTransport[] currentSessions = activeSessions.Values.ToArray();
    for (int i = 0; i < currentSessions.Length; i++)
    {
        var session = currentSessions[i];
        if (DateTime.UtcNow.Subtract(session.LastUsed).TotalMilliseconds > INACTIVE_SESSION_TIMEOUT)
        {
            session.Close();
            Console.WriteLine($"Closed inactive session with {session.RemoteEndpoint}");
        }
    }
}, null, INACTIVE_SESSION_TIMEOUT, INACTIVE_SESSION_TIMEOUT / 2);

listenSocket.Bind(localEndpoint);
Console.WriteLine($"DTLS Server is listening on {localEndpoint}");

while (!isShutdown)
{
    int length = 0;
    try
    {
        length = listenSocket.ReceiveFrom(buffer, ref remoteEndpoint);
    }
    catch(SocketException ex)
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
            DtlsRequest request = null;

            // optionally start with HelloVerify
            if (isHelloVerifyEnabled)
            {
                var clientID = remoteEndpoint.Serialize().Buffer.ToArray();
                request = verifier.VerifyRequest(clientID, buffer, 0, length, new UdpSender(listenSocket, remoteEndpoint, UdpTransport.MTU));

                if (request == null)
                {
                    Console.WriteLine($"Sent HelloVerify to {remoteEndpoint}");
                }
                else
                {
                    Console.WriteLine($"HelloVerify from {remoteEndpoint} succeeded");
                }
            }

            // negotiate DTLS
            if (request != null || !isHelloVerifyEnabled)
            {
                UdpTransport udpServerTransport = new UdpTransport(listenSocket, remoteEndpoint, UdpTransport.MTU, (transport) => activeSessions.TryRemove(transport.RemoteEndpoint, out _));
                if (activeSessions.TryAdd(remoteEndpoint.ToString(), udpServerTransport))
                {
                    udpServerTransport.TryAddToReceiveQueue(buffer.Take(length).ToArray());

                    var session = Task.Run(() =>
                    {
                        Console.WriteLine($"Beginning handshake with {remoteEndpoint}");
                        DtlsTransport dtlsTransport = server.DoHandshake(udpServerTransport, out string error, request);

                        if (dtlsTransport != null)
                        {
                            Console.WriteLine($"DTLS connected");
                            byte[] receiveBuffer = new byte[dtlsTransport.GetReceiveLimit()];

                            while (!isShutdown)
                            {
                                int length = dtlsTransport.Receive(receiveBuffer, 0, receiveBuffer.Length, 1000);
                                if (length > 0)
                                {
                                    Console.WriteLine($"Received {receiveBuffer[0]} from {remoteEndpoint}");
                                    dtlsTransport.Send(receiveBuffer, 0, length);
                                }
                            }

                            dtlsTransport.Close();
                        }
                        else
                        {
                            Console.WriteLine($"Handshake with {remoteEndpoint} failed with {error}");
                            activeSessions.TryRemove(remoteEndpoint.ToString(), out _);
                        }
                    });
                }
            }
        }
    }
}
