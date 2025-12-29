using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;

namespace SharpSRTP.DTLS
{
    public class DTLSCertificateUtils
    {
        public static (Certificate certificate, AsymmetricKeyParameter key) GenerateServerCertificate(
            string name,
            DateTime notBefore,
            DateTime notAfter,
            bool useRSA)
        {
            if (useRSA)
            {
                return GenerateRSAServerCertificate(name, notBefore, notAfter);
            }
            else
            {
                return GenerateECDSAServerCertificate(name, notBefore, notAfter);
            }
        }

        public static (Certificate certificate, AsymmetricKeyParameter key) GenerateRSAServerCertificate(
            string name,
            DateTime notBefore,
            DateTime notAfter,
            bool exClientAuth = true,
            int keyStrength = 2048,
            string signatureAlgorithm = "SHA256WITHRSA")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            var nameOids = new List<DerObjectIdentifier>
            {
                X509Name.CN
            };

            var nameValues = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, name }
            };

            var subjectDN = new X509Name(nameOids, nameValues);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            if (exClientAuth)
            {
                var keyUsage = new KeyUsage(KeyUsage.DigitalSignature);
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, keyUsage.ToAsn1Object());

                var extendedKeyUsage = new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_serverAuth });
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, extendedKeyUsage.ToAsn1Object());
            }

            byte[] serial = new byte[20];
            random.NextBytes(serial);
            serial[0] = 1;
            certificateGenerator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(serial));

            X509Certificate x509Certificate = certificateGenerator.Generate(signatureFactory);
            AsymmetricKeyParameter privateKey = issuerKeyPair.Private;

            var crypto = new BcTlsCrypto();
            var tlsCertificate = crypto.CreateCertificate(x509Certificate.GetEncoded());
            var certificate = new Certificate(new TlsCertificate[] { tlsCertificate });

            return (certificate, privateKey);
        }

        public static (Certificate certificate, AsymmetricKeyParameter key) GenerateECDSAServerCertificate(
            string name,
            DateTime notBefore,
            DateTime notAfter,
            bool exClientAuth = true,
            string curve = "prime256v1",
            string signatureAlgorithm = "SHA256WITHECDSA")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var spec = ECNamedCurveTable.GetByName(curve);
            var keyPairGenerator = new ECKeyPairGenerator("EC");
            ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(new ECDomainParameters(spec.Curve, spec.G, spec.N), random);
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            var nameOids = new List<DerObjectIdentifier>
            {
                X509Name.CN
            };

            var nameValues = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, name }
            };

            var subjectDN = new X509Name(nameOids, nameValues);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            if (exClientAuth)
            {
                var keyUsage = new KeyUsage(KeyUsage.DigitalSignature);
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, keyUsage.ToAsn1Object());

                var extendedKeyUsage = new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_serverAuth });
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, extendedKeyUsage.ToAsn1Object());
            }

            byte[] serial = new byte[20];
            random.NextBytes(serial);
            serial[0] = 1;
            certificateGenerator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(serial));

            X509Certificate x509Certificate = certificateGenerator.Generate(signatureFactory);
            AsymmetricKeyParameter privateKey = issuerKeyPair.Private;

            var crypto = new BcTlsCrypto();
            var tlsCertificate = crypto.CreateCertificate(x509Certificate.GetEncoded());
            var certificate = new Certificate(new[] { tlsCertificate });

            return (certificate, privateKey);
        }

        public static string Fingerprint(X509CertificateStructure c, string algorithm = "SHA256")
        {
            byte[] der = c.GetEncoded();
            byte[] hash = DigestUtilities.CalculateDigest(algorithm, der);
            byte[] hexBytes = Hex.Encode(hash);
            string hex = Encoding.ASCII.GetString(hexBytes).ToUpperInvariant();

            StringBuilder fp = new StringBuilder();
            int i = 0;
            fp.Append(hex.Substring(i, 2));
            while ((i += 2) < hex.Length)
            {
                fp.Append(':');
                fp.Append(hex.Substring(i, 2));
            }
            return fp.ToString();
        }

        public static bool IsHashSupported(string algStr)
        {
            string algName = algStr.ToLowerInvariant();
            return algName == "sha-256" || algName == "sha256";
        }
    }
}