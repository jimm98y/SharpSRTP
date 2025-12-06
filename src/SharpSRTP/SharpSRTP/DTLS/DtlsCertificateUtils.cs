using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpSRTP.DTLS
{
    public class DtlsCertificateUtils
    {
        public static (string certificate, string key) GenerateServerCertificate(
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

            var certificate = certificateGenerator.Generate(signatureFactory);
            var privateKey = issuerKeyPair.Private;
            var pkcs8 = new Pkcs8Generator(privateKey);

            string strCertificate = "";
            string strKey = "";

            using (var textWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(textWriter))
                {
                    pemWriter.WriteObject(certificate);
                }

                strCertificate = textWriter.ToString();
            }

            using (var textWriter = new StringWriter())
            {
                using (PemWriter pemWriter = new PemWriter(textWriter))
                {
                    pemWriter.WriteObject(pkcs8);
                }

                strKey = textWriter.ToString();
            }

            return (strCertificate, strKey);
        }

        public static string Fingerprint(X509CertificateStructure c)
        {
            byte[] der = c.GetEncoded();
            byte[] hash = Sha256DigestOf(der);
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

        public static byte[] Sha256DigestOf(byte[] input)
        {
            return DigestUtilities.CalculateDigest("SHA256", input);
        }
    }
}