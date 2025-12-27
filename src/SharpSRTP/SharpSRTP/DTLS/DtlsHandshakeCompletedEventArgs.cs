using Org.BouncyCastle.Tls;
using System;

namespace SharpSRTP.DTLS
{
    public class DTLSHandshakeCompletedEventArgs : EventArgs
    {
        public DTLSHandshakeCompletedEventArgs(SecurityParameters securityParameters)
        {
            SecurityParameters = securityParameters;
        }

        public SecurityParameters SecurityParameters { get; }
    }
}