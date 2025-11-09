using Org.BouncyCastle.Tls;
using System;
using System.Net;
using System.Net.Sockets;

namespace DtlsSample
{
    public class UdpDatagramTransport : DatagramTransport
    {
        private readonly int _mtu = 1472;

        private UdpClient _udpClient = null;
        private IPEndPoint _remote;

        public UdpDatagramTransport(int mtu = 1472)
        {
            this._mtu = mtu;
            this._udpClient = new UdpClient();
        }

        public virtual void Connect(string endpoint)
        {
            _remote = IPEndPoint.Parse(endpoint);
        }

        public virtual void Listen(string endpoint)
        {
            this._udpClient = new UdpClient(IPEndPoint.Parse(endpoint));
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
            _udpClient.Send(buffer, _remote);
        }

        public virtual void Close()
        {
            _udpClient.Close();
        }
    }
}
