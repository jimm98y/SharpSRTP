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
using System.Net;
using System.Net.Sockets;

namespace SharpSRTP.UDP
{
    /// <summary>
    /// Simple UDP sender to be used with <see cref="DtlsVerifier"/>.
    /// </summary>
    public class UdpSender : DatagramSender
    {
        private readonly Socket _socket;
        private readonly EndPoint _remote;
        private readonly int _mtu;

        public UdpSender(Socket socket, EndPoint remote, int mtu)
        {
            this._socket = socket ?? throw new ArgumentNullException(nameof(socket));
            this._remote = remote ?? throw new ArgumentNullException(nameof(remote));
            this._mtu = mtu;
        }

        public int GetSendLimit()
        {
            return _mtu;
        }

        public void Send(byte[] buf, int off, int len)
        {
            _socket.SendTo(buf.AsSpan(off, len).ToArray(), _remote);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public void Send(ReadOnlySpan<byte> buffer)
        {
            _socket.SendTo(buffer, _remote);
        }
#endif
    }
}
