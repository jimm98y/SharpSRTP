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
using System.Net;

namespace SharpSRTP.DTLS
{
    /// <summary>
    /// A ClientHello that passed the server's stateless cookie exchange. Pass it to <see cref="IDtlsPeer.DoHandshake"/>.
    /// </summary>
    public interface IDtlsRequest
    {
        EndPoint RemoteEndpoint { get; }
    }

    public interface IDtlsServerPeer : IDtlsPeer
    {
        /// <summary>
        /// Stateless cookie check of a datagram from an unknown peer (RFC 6347 §4.2.1, RFC 9147 §5.1).
        /// </summary>
        /// <returns>
        /// The verified request, or null after answering with a HelloVerifyRequest/HelloRetryRequest through
        /// <paramref name="sender"/> (or dropping a datagram that is not a ClientHello). No state is kept for the peer.
        /// </returns>
        IDtlsRequest VerifyRequest(EndPoint remoteEndpoint, byte[] data, int offset, int length, DatagramSender sender);
    }
}
