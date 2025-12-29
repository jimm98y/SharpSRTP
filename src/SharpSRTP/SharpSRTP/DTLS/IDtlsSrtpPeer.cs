using Org.BouncyCastle.Tls;
using System;

namespace SharpSRTP.DTLS
{
    public enum AlertLevelsEnum
    {
        Warn = 1,
        Fatal = 2
    }

    public enum AlertTypesEnum
    {
        CloseNotify = 0,
        Unknown = 255
    }

    public delegate void OnDtlsAlertEvent(AlertLevelsEnum alertLevel, AlertTypesEnum alertType, string alertDescription);

    public class DtlsHandshakeCompletedEventArgs : EventArgs
    {
        public DtlsHandshakeCompletedEventArgs(SecurityParameters securityParameters)
        {
            SecurityParameters = securityParameters;
        }

        public SecurityParameters SecurityParameters { get; }
    }

    public interface IDtlsSrtpPeer
    {
        event OnDtlsAlertEvent OnAlert;
        Certificate PeerCertificate { get; }
    }
}
