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
using System;
using System.Collections.Concurrent;
using TlsConnectionBase = SharpDTLS.TlsConnectionBase;

namespace SharpDtlsAdapter
{
    /// <summary>
    /// <see cref="IDtlsTransport"/> over a SharpDTLS connection. Like BouncyCastle's DtlsTransport it is pull-based:
    /// datagrams are only read from the underlying <see cref="DatagramTransport"/> inside <see cref="Receive"/>.
    /// </summary>
    internal sealed class SharpDtlsTransport : IDtlsTransport
    {
        // Worst-case record expansion: DTLS 1.2 header (13) + CBC IV (16) + HMAC-SHA384 (48) + padding (16).
        private const int MaxRecordOverhead = 93;

        private readonly TlsConnectionBase _connection;
        private readonly DatagramTransport _transport;
        private readonly Func<int, bool> _pump;
        private readonly ConcurrentQueue<byte[]> _received;

        public SharpDtlsTransport(TlsConnectionBase connection, DatagramTransport transport, Func<int, bool> pump, ConcurrentQueue<byte[]> received)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _pump = pump ?? throw new ArgumentNullException(nameof(pump));
            _received = received ?? throw new ArgumentNullException(nameof(received));
        }

        public int GetReceiveLimit() => _transport.GetReceiveLimit();

        public int GetSendLimit() => Math.Min(_connection.MaxApplicationDataSize, _transport.GetSendLimit() - MaxRecordOverhead);

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            long deadline = Environment.TickCount64 + waitMillis;
            while (true)
            {
                if (_received.TryDequeue(out byte[] data))
                {
                    int length = Math.Min(len, data.Length);
                    Buffer.BlockCopy(data, 0, buf, off, length);
                    return length;
                }

                int remaining = (int)(deadline - Environment.TickCount64);
                if (_connection.IsClosed || remaining <= 0)
                {
                    return -1;
                }

                _pump(remaining);
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            // SharpDTLS builds the record right away and keeps no reference, so a whole array needs no copy
            byte[] data = buf;
            if (off != 0 || len != buf.Length)
            {
                data = new byte[len];
                Buffer.BlockCopy(buf, off, data, 0, len);
            }

            _connection.SendApplicationData(data);
        }

        public void Close()
        {
            _connection.Close();
            _transport.Close();
        }
    }
}
