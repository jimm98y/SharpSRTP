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

### DTLS Client

## SRTP
### SRTP Server

### SRTP Client

## DTLS-SRTP
### DTLS-SRTP Server

### DTLS-SRTP Client

## TODO
1. Double Encryption Procedures for the Secure Real-Time Transport Protocol (SRTP) [RFC 8723](https://datatracker.ietf.org/doc/html/rfc8723)