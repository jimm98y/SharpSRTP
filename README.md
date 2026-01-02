# SharpSRTP
DTLS, DTLS-SRTP and SRTP/SRTCP client and server written in C#. Implements the following RFCs:
1. The Secure Real-time Transport Protocol (SRTP) [RFC3711](https://www.rfc-editor.org/rfc/rfc3711)
1. Session Description Protocol (SDP) Security Descriptions for Media Streams [RFC4568](https://datatracker.ietf.org/doc/html/rfc4568)
1. The SEED Cipher Algorithm and Its Use with the Secure Real-Time Transport Protocol (SRTP) [RFC5669](https://datatracker.ietf.org/doc/html/rfc5669)
1. Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP) [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. The Use of AES-192 and AES-256 in Secure RTP [RFC6188](https://datatracker.ietf.org/doc/html/rfc6188)
1. AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol (SRTP) [RFC7714](https://datatracker.ietf.org/doc/html/rfc7714)
1. The ARIA Algorithm and Its Use with the Secure Real-Time Transport Protocol (SRTP) [RFC8269](https://datatracker.ietf.org/doc/html/rfc8269)

## SRTP Crypto Suites
Implemented [SRTP Crypto Suites](https://www.iana.org/assignments/sdp-security-descriptions/sdp-security-descriptions.xhtml) are:
1. AES_CM_128_HMAC_SHA1_80 [RFC4568](https://datatracker.ietf.org/doc/html/rfc4568)
1. AES_CM_128_HMAC_SHA1_32 [RFC4568](https://datatracker.ietf.org/doc/html/rfc4568)
1. F8_128_HMAC_SHA1_80 [RFC4568](https://datatracker.ietf.org/doc/html/rfc4568)
1. SEED_CTR_128_HMAC_SHA1_80 [RFC5669](https://datatracker.ietf.org/doc/html/rfc5669)
1. SEED_128_CCM_80 [RFC5669](https://datatracker.ietf.org/doc/html/rfc5669)
1. SEED_128_GCM_96 [RFC5669](https://datatracker.ietf.org/doc/html/rfc5669)
1. AES_192_CM_HMAC_SHA1_80 [RFC6188](https://datatracker.ietf.org/doc/html/rfc6188)
1. AES_192_CM_HMAC_SHA1_32 [RFC6188](https://datatracker.ietf.org/doc/html/rfc6188)
1. AES_256_CM_HMAC_SHA1_80 [RFC6188](https://datatracker.ietf.org/doc/html/rfc6188)
1. AES_256_CM_HMAC_SHA1_32 [RFC6188](https://datatracker.ietf.org/doc/html/rfc6188)
1. AEAD_AES_128_GCM [RFC7714](https://datatracker.ietf.org/doc/html/rfc7714)
1. AEAD_AES_256_GCM [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)

## DTLS-SRTP Protection Profiles
Implemented [DTLS-SRTP protection profiles](https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml) are:
1. SRTP_AES128_CM_HMAC_SHA1_80 [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. SRTP_AES128_CM_HMAC_SHA1_32 [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. SRTP_NULL_HMAC_SHA1_80 [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. SRTP_NULL_HMAC_SHA1_32 [RFC5764](https://www.rfc-editor.org/rfc/rfc5764)
1. SRTP_AEAD_AES_128_GCM [RFC7714](https://datatracker.ietf.org/doc/html/rfc7714)
1. SRTP_AEAD_AES_256_GCM [RFC7714](https://datatracker.ietf.org/doc/html/rfc7714)
1. SRTP_ARIA_128_CTR_HMAC_SHA1_80 [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)
1. SRTP_ARIA_128_CTR_HMAC_SHA1_32 [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)
1. SRTP_ARIA_256_CTR_HMAC_SHA1_80 [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)
1. SRTP_ARIA_256_CTR_HMAC_SHA1_32 [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)
1. SRTP_AEAD_ARIA_128_GCM [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)
1. SRTP_AEAD_ARIA_256_GCM [RFC8269](https://datatracker.ietf.org/doc/html/rfc4568)

## DTLS
The current DTLS implementation is based upon BouncyCastle and supports DTLS 1.2 only.

### DTLS Server
Start with generating the TLS certificate. Self-signed RSA SHA256 certificate can be generated as follows:
```cs
var rsaCertificate = DtlsCertificateUtils.GenerateCertificate("DTLS", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), true);
```
Create the DTLS server and subscribe the OnHandshakeCompleted event to get notified when a client connects:
```cs
DtlsServer server = new DtlsServer(rsaCertificate.certificate, rsaCertificate.key, SignatureAlgorithm.rsa, HashAlgorithm.sha256);
server.OnHandshakeCompleted += (sender, e) =>
{
    ...
};
````
Create the DTLS transport. Here we will use UDP on localhost, port 8888:
```cs
UdpDatagramTransport udpServerTransport = new UdpDatagramTransport("127.0.0.1:8888", null);
```
Wait for the client and perform DTLS handshake:
```cs
bool isShutdown = false;
while(!isShutdown)
{
    DtlsTransport dtlsTransport = server.DoHandshake(
        out string error,
        udpServerTransport, 
        () =>
        {
            return udpServerTransport.RemoteEndPoint.ToString();
        },
        (remoteEndpoint) =>
        {
            return new UdpDatagramTransport(null, remoteEndpoint);
        });
        
        var session = Task.Run(() =>
        {
            ...
        });
}
```
Receive data from the client:
```cs
byte[] buffer = new byte[dtlsTransport.GetReceiveLimit()];
int receivedLength = dtlsTransport.Receive(buffer, 0, buffer.Length, 100);
```
Send data to the client:
```cs
dtlsTransport.Send(buffer, 0, buffer.Length);
```
To modify the offered crypto suites for the DTLS handshake, simply override `GetSupportedCipherSuites` and return a different set of crypto suites. To support a different version of DTLS, override `GetSupportedVersions` and return a different version. Note that as of January 2026, BouncyCastle still does not support DTLS 1.3.
### DTLS Client
Start with creating the TLS certificate. Certificate type of the client must match the certificate type on the server, meaning if the server uses RSA certificate, the client has to use RSA certificate as well:
```cs
var rsaCertificate = DtlsCertificateUtils.GenerateCertificate("DTLS", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), true);
```
Create the DTLS client:
```cs
DtlsClient client = new DtlsClient(null, rsaCertificate.certificate, rsaCertificate.key, SignatureAlgorithm.rsa, HashAlgorithm.sha256);
```
Optionally, you can let the client auto-generate the matching certificate:
```cs
DtlsClient client = new DtlsClient();
```
Subscribe for `OnHandshakeCompleted`:
```cs
client.OnHandshakeCompleted += (sender, e) =>
{
    ...
};
```
Create the DTLS transport. Here we will use UDP on localhost, port 8888:
```cs
UdpDatagramTransport udpServerTransport = new UdpDatagramTransport(null, "127.0.0.1:8888");
```
Connect the client:
```cs
DtlsTransport dtlsTransport = client.DoHandshake(out string error, udpClientTransport);
```
Receive data to the server:
```cs
dtlsTransport.Send(buffer, 0, buffer.Length);
```
Receive data from the server:
```cs
byte[] buffer = new byte[dtlsTransport.GetReceiveLimit()];
int receivedLength = dtlsTransport.Receive(buffer, 0, buffer.Length, 100);
```
Close the transport:
```cs
dtlsTransport.Close();
```
## SRTP
### SRTP Server

### SRTP Client

## DTLS-SRTP
### DTLS-SRTP Server

### DTLS-SRTP Client

## TODO
1. Double Encryption Procedures for the Secure Real-Time Transport Protocol (SRTP) [RFC8723](https://datatracker.ietf.org/doc/html/rfc8723)