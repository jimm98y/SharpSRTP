using Org.BouncyCastle.Tls;
using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SharpSRTP.DTLS
{
    public class UdpDatagramTransport : DatagramTransport
    {
        private readonly int _mtu = 1472;

        private UdpClient _udpClient = null;
        private IPEndPoint _remote;
        public IPEndPoint RemoteEndPoint => _remote;

        public UdpDatagramTransport(string localEndpoint, string remoteEndpoint, int mtu = 1472)
        {
            this._mtu = mtu;
            if (string.IsNullOrEmpty(localEndpoint))
            {
                this._udpClient = new UdpClient();
            }
            else
            {
#if NETFRAMEWORK || NETSTANDARD
                var endpoint = IPEndPointExtensions.Parse(localEndpoint);
#else
                var endpoint = IPEndPoint.Parse(localEndpoint);
#endif
                this._udpClient = new UdpClient(endpoint);
            }

            if (!string.IsNullOrEmpty(remoteEndpoint))
            {
#if NETFRAMEWORK || NETSTANDARD
                _remote = IPEndPointExtensions.Parse(remoteEndpoint);
#else
                _remote = IPEndPoint.Parse(remoteEndpoint);
#endif
            }
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
            _remote = new IPEndPoint(IPAddress.Any, 0);
            byte[] receivedBytes = _udpClient.Receive(ref _remote);
            receivedBytes.AsSpan().CopyTo(buffer);
            return receivedBytes.Length;
        }

        public virtual void Send(byte[] buf, int off, int len)
        {
            Send(buf.AsSpan(off, len));
        }

        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
#if NETFRAMEWORK || NETSTANDARD
            _udpClient.Send(buffer.ToArray(), buffer.Length, _remote);
#else
            _udpClient.Send(buffer, _remote);
#endif
        }

        public virtual void Close()
        {
            _udpClient.Close();
        }
    }

#if NETFRAMEWORK || NETSTANDARD
    public static class IPEndPointExtensions
    {
        public static bool TryParse(string s, out IPEndPoint result)
        {
            int addressLength = s.Length;  // If there's no port then send the entire string to the address parser
            int lastColonPos = s.LastIndexOf(':');

            // Look to see if this is an IPv6 address with a port.
            if (lastColonPos > 0)
            {
                if (s[lastColonPos - 1] == ']')
                {
                    addressLength = lastColonPos;
                }
                // Look to see if this is IPv4 with a port (IPv6 will have another colon)
                else if (s.Substring(0, lastColonPos).LastIndexOf(':') == -1)
                {
                    addressLength = lastColonPos;
                }
            }

            if (IPAddress.TryParse(s.Substring(0, addressLength), out IPAddress address))
            {
                uint port = 0;

                if (addressLength == s.Length ||
                    (uint.TryParse(s.Substring(addressLength + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port <= IPEndPoint.MaxPort))

                {
                    result = new IPEndPoint(address, (int)port);

                    return true;
                }
            }

            result = null;

            return false;
        }

        public static IPEndPoint Parse(string s)
        {
            if (s == null)
            {
                throw new ArgumentNullException(nameof(s));
            }

            if (TryParse(s, out IPEndPoint result))
            {
                return result;
            }

            throw new FormatException(@"An invalid IPEndPoint was specified.");
        }
    }
#endif
}
