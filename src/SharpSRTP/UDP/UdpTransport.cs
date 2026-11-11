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
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace SharpSRTP.UDP
{
    /// <summary>
    /// UDP transport.
    /// </summary>
    public class UdpTransport : DatagramTransport
    {
        public const int MAX_RECEIVE_QUEUE_ITEMS = 32;
        public const int MTU = 1472; // 1500 - 20 (IP) - 8 (UDP)

        // ReceiveFrom only uses it as the address family template, the sender's address is returned in a new instance
        private static readonly EndPoint AnyEndPoint = new IPEndPoint(IPAddress.Any, 0);

        private readonly Socket _socket;
        private readonly EndPoint _remote;
        private readonly int _mtu = MTU;
        private readonly Action<UdpTransport> _onClose;
        private readonly BlockingCollection<byte[]> _receiveQueue = new BlockingCollection<byte[]>();

        public string RemoteEndpoint { get { return _remote?.ToString(); } }
        public DateTime LastReceived { get; private set; } = DateTime.UtcNow;
        public DateTime LastSent { get; private set; } = DateTime.UtcNow;
        public DateTime LastUsed { get { return LastReceived > LastSent ? LastReceived : LastSent; } }

        public UdpTransport(Socket socket, EndPoint remote = null, int mtu = MTU, Action<UdpTransport> onClose = null)
        {
            this._socket = socket ?? throw new ArgumentNullException(nameof(socket));
            this._remote = remote;
            this._mtu = mtu;
            this._onClose = onClose;
        }

        /// <summary>Takes the next queued datagram as it was added, without copying it.</summary>
        public bool TryTakeFromReceiveQueue(out byte[] data, int waitMillis)
        {
            return _receiveQueue.TryTake(out data, waitMillis);
        }

        public bool TryAddToReceiveQueue(byte[] data, int maxReceiveQueueSize = MAX_RECEIVE_QUEUE_ITEMS)
        {
            LastReceived = DateTime.UtcNow;
            if (_receiveQueue.Count > maxReceiveQueueSize)
            {
                return false;
            }
            _receiveQueue.Add(data);
            return true;
        }

        public virtual int GetReceiveLimit()
        {
            return _mtu;
        }

        public virtual int GetSendLimit()
        {
            return _mtu;
        }

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            if (_remote == null)
            {
                return ReceiveFromSocket(buf, off, len, waitMillis);
            }

            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            if (_remote == null)
            {
#if NET8_0_OR_GREATER
                try
                {
                    if (!WaitForData(waitMillis))
                    {
                        return -1;
                    }
                    EndPoint remote = AnyEndPoint;
                    return this._socket.ReceiveFrom(buffer, ref remote);
                }
                catch (SocketException)
                {
                    return -1;
                }
#else
                // no span overloads on the socket here: receive into a pooled array and copy only what arrived
                byte[] rented = ArrayPool<byte>.Shared.Rent(buffer.Length);
                try
                {
                    int len = ReceiveFromSocket(rented, 0, buffer.Length, waitMillis);
                    if (len > 0)
                    {
                        rented.AsSpan(0, len).CopyTo(buffer);
                    }
                    return len;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
#endif
            }
            else
            {
                if (_receiveQueue.TryTake(out byte[] data, waitMillis))
                {
                    data.AsSpan().CopyTo(buffer);
                    return data.Length;
                }
                return -1;
            }
        }

        private int ReceiveFromSocket(byte[] buf, int off, int len, int waitMillis)
        {
            try
            {
                if (!WaitForData(waitMillis))
                {
                    return -1;
                }
                EndPoint remote = AnyEndPoint;
                return this._socket.ReceiveFrom(buf, off, len, SocketFlags.None, ref remote);
            }
            catch (SocketException)
            {
                return -1;
            }
        }

        /// <summary>
        /// Waits up to <paramref name="waitMillis"/> (0 or less: indefinitely) for a datagram. Polling rather than setting
        /// Socket.ReceiveTimeout: a receive that times out leaves a Windows socket in an indeterminate state, and a datagram
        /// arriving at that moment can be lost.
        /// </summary>
        private bool WaitForData(int waitMillis)
            => this._socket.Poll(waitMillis <= 0 ? -1 : (int)Math.Min((long)waitMillis * 1000, int.MaxValue), SelectMode.SelectRead);

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (len > GetSendLimit())
            {
                /*
                 * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
                 * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
                 * which will be fragmented."
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            SendToSocket(buf, off, len);
        }

        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
#if NET8_0_OR_GREATER
            LastSent = DateTime.UtcNow;

            if (_remote == null)
            {
                _socket.Send(buffer);
            }
            else
            {
                _socket.SendTo(buffer, _remote);
            }
#else
            // no span overloads on the socket here: send from a pooled array
            byte[] rented = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                buffer.CopyTo(rented);
                SendToSocket(rented, 0, buffer.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
#endif
        }

        private void SendToSocket(byte[] buf, int off, int len)
        {
            LastSent = DateTime.UtcNow;

            if (_remote == null)
            {
                _socket.Send(buf, off, len, SocketFlags.None);
            }
            else
            {
                _socket.SendTo(buf, off, len, SocketFlags.None, _remote);
            }
        }

        public virtual void Close()
        {
            _onClose?.Invoke(this);
        }
    }
}
