using Org.BouncyCastle.Tls;
using System;

namespace SharpSRTP.DTLS
{
    public class DtlsHandshakeCompletedEventArgs : EventArgs
    {
        public DtlsHandshakeCompletedEventArgs(SecurityParameters securityParameters)
        {
            SecurityParameters = securityParameters;
        }

        public SecurityParameters SecurityParameters { get; }
    }
}