// SharpSRTP
// Copyright (C) 2025 Lukas Volf
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using SharpSRTP.UDP;
using System;
using System.Net;
using IClientTransport = SharpDTLS.UDP.IClientTransport;
using IServerTransport = SharpDTLS.UDP.IServerTransport;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// SharpDTLS client transport over a pull-based <see cref="DatagramTransport"/>: received datagrams are only
    /// delivered while somebody calls <see cref="Pump"/>, so no background thread competes for the socket.
    /// </summary>
    internal sealed class ClientTransportAdapter : IClientTransport
    {
        private readonly DatagramTransport _transport;
        private readonly DatagramReader _reader;

        public event EventHandler<byte[]> OnDataReceived;

        public ClientTransportAdapter(DatagramTransport transport)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _reader = new DatagramReader(transport);
        }

        public void Send(byte[] buf) => _transport.Send(buf, 0, buf.Length);

        /// <summary>Waits up to <paramref name="waitMillis"/> for one datagram and delivers it; false on timeout.</summary>
        public bool Pump(int waitMillis)
        {
            byte[] datagram = _reader.Read(waitMillis);
            if (datagram == null)
            {
                return false;
            }

            OnDataReceived?.Invoke(this, datagram);
            return true;
        }
    }

    /// <summary>
    /// Reads datagrams as arrays of their own, which SharpDTLS takes over: a server-side <see cref="UdpTransport"/>
    /// already queues them that way, anything else is read into a buffer and copied.
    /// </summary>
    internal sealed class DatagramReader
    {
        private readonly DatagramTransport _transport;
        private readonly UdpTransport _queue;
        private readonly byte[] _buffer;

        public DatagramReader(DatagramTransport transport)
        {
            _transport = transport;
            _queue = transport is UdpTransport udp && udp.RemoteEndpoint != null ? udp : null;
            _buffer = _queue == null ? new byte[transport.GetReceiveLimit()] : null;
        }

        /// <summary>Waits up to <paramref name="waitMillis"/> for one datagram; null on timeout.</summary>
        public byte[] Read(int waitMillis)
        {
            // UdpTransport sets Socket.ReceiveTimeout from the wait, where 0 would mean "forever".
            waitMillis = Math.Max(1, waitMillis);
            if (_queue != null)
            {
                return _queue.TryTakeFromReceiveQueue(out byte[] datagram, waitMillis) && datagram.Length > 0 ? datagram : null;
            }

            int length = _transport.Receive(_buffer, 0, _buffer.Length, waitMillis);
            return length > 0 ? _buffer.AsSpan(0, length).ToArray() : null;
        }
    }

    /// <summary>
    /// SharpDTLS server transport for a single peer over its <see cref="DatagramTransport"/>; the server and its connection
    /// are referenced only from what <see cref="DtlsServer.DoHandshake"/> returns, so they go away with it.
    /// </summary>
    internal sealed class PeerServerTransport : IServerTransport
    {
        private readonly DatagramTransport _transport;
        private readonly DatagramReader _reader;

        public event EventHandler<byte[]> OnDataReceived;

        public PeerServerTransport(DatagramTransport transport, EndPoint endpoint)
        {
            _transport = transport;
            _reader = new DatagramReader(transport);
            Endpoint = endpoint;
        }

        public EndPoint Endpoint { get; }

        public void Send(EndPoint endpoint, byte[] buf) => _transport.Send(buf, 0, buf.Length);

        /// <summary>Waits up to <paramref name="waitMillis"/> for one datagram and delivers it; false on timeout.</summary>
        public bool Pump(int waitMillis)
        {
            byte[] datagram = _reader.Read(waitMillis);
            if (datagram == null)
            {
                return false;
            }

            OnDataReceived?.Invoke(Endpoint, datagram);
            return true;
        }

        /// <summary>
        /// The peer address of <paramref name="transport"/>, which its cookie is bound to; a placeholder when the transport
        /// does not tell (such a peer simply goes through the server's own cookie exchange).
        /// </summary>
        public static IPEndPoint EndpointOf(DatagramTransport transport, IDtlsRequest request)
        {
            if (transport is UdpTransport udp && udp.RemoteEndpoint != null && IPEndPointExtensions.TryParse(udp.RemoteEndpoint, out IPEndPoint endpoint))
            {
                return endpoint;
            }

            if (request?.RemoteEndpoint is IPEndPoint verified)
            {
                return new IPEndPoint(verified.Address, verified.Port);
            }

            return new IPEndPoint(IPAddress.IPv6None, 0);
        }
    }

    /// <summary>
    /// Transport of the server that only verifies cookies: its replies (HelloVerifyRequest, HelloRetryRequest, alerts) go
    /// through the <see cref="DatagramSender"/> of the datagram being verified.
    /// </summary>
    internal sealed class VerifierServerTransport : IServerTransport
    {
#pragma warning disable CS0067 // the verifier is handed datagrams directly, never through the transport
        public event EventHandler<byte[]> OnDataReceived;
#pragma warning restore CS0067

        public DatagramSender Sender { get; set; }

        public void Send(EndPoint endpoint, byte[] buf) => Sender?.Send(buf, 0, buf.Length);
    }
}
