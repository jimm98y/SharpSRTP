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

        private readonly Socket _socket;
        private readonly EndPoint _remote;
        private readonly int _mtu = MTU;
        private readonly Action<UdpTransport> _onClose;
        private readonly BlockingCollection<byte[]> _receiveQueue = new BlockingCollection<byte[]>();

        public string RemoteEndpoint { get { return _remote.ToString(); } }
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
            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            if (_remote == null)
            {
                this._socket.ReceiveTimeout = waitMillis;
                try
                {
                    EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    var byteBuffer = buffer.ToArray();
                    int len = this._socket.ReceiveFrom(byteBuffer, ref remote);
                    byteBuffer.AsSpan().CopyTo(buffer);
                    return len;
                }
                catch(SocketException)
                {
                    return -1;
                }
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

            Send(buf.AsSpan(off, len));
        }

        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            LastSent = DateTime.UtcNow;

            if (_remote == null)
            {
                _socket.Send(buffer.ToArray());
            }
            else
            {
                _socket.SendTo(buffer.ToArray(), _remote);
            }
        }

        public virtual void Close()
        {
            _onClose?.Invoke(this);
        }
    }
}
