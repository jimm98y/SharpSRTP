using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Threading;

namespace SharpSRTP.SRTP
{
    public enum SRTPContextType
    {
        RTP,
        RTCP
    }

    public class SRTPContext
    {
        private const int REPLAY_WINDOW_SIZE = 64; // Minumum is 64 according to the RFC, our current implmentation is using a bit mask, so it won't allow more than 64.

        private ulong _bitmap = 0; /* session state - must be 32 bits */
        private uint _lastSeq = 0; /* session state */
        private readonly SRTPContextType _contextType;

        public event EventHandler<EventArgs> OnRekeyingRequested;

        public HMac HMAC { get; private set; }
        public AesEngine AES { get; private set; }
        public AesEngine AESF8 { get; private set; }
        public AriaEngine ARIA { get; private set; }
        public GcmBlockCipher AESGCM { get; private set; }
        public GcmBlockCipher ARIAGCM { get; private set; }

        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public uint S_l { get { return _lastSeq; } set { _lastSeq = value; } }
        public bool S_l_set { get; set; } = false;

        public int ProtectionProfile { get; set; } = Org.BouncyCastle.Tls.ExtendedSrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80;
        public SRTPCiphers Cipher { get; set; } = SRTPCiphers.AES_128_CM;
        public SRTPAuth Auth { get; set; } = SRTPAuth.HMAC_SHA1;

        public byte[] MasterKey { get; set; }
        public byte[] MasterSalt { get; set; }

        /// <summary>
        /// Rollover counter.
        /// </summary>
        public uint Roc { get; set; } = 0;

        #region TODO Master key lifespan

        private long _masterKeySentCounter = 0;

        /// <summary>
        /// Specified how many times was the current master key used.
        /// </summary>
        public long MasterKeySentCounter { get { return _masterKeySentCounter; } }

        /// <summary>
        /// Key derivation rate.
        /// </summary>
        public ulong KeyDerivationRate { get; set; } = 0;

        /// <summary>
        /// From, To values, specifying the lifetime for a master key.
        /// </summary>
        //public int From { get; set; }
        //public int To { get; set; }

        /// <summary>
        /// Master Key Identifier.
        /// </summary>
        public byte[] Mki { get; set; }

        #endregion // TODO Master key lifespan

        #region Session key parameters

        /// <summary>
        /// The byte-length of the session keys for encryption.
        /// </summary>
        public int N_e { get; set; } = 16;

        /// <summary>
        /// Session key for encryption.
        /// </summary>
        public byte[] K_e { get; set; }

        /// <summary>
        /// The byte-length of k_s.
        /// </summary>
        public int N_s { get; set; } = 14;

        /// <summary>
        /// Session salting key.
        /// </summary>
        public byte[] K_s { get; set; }

        #endregion // Session key parameters

        #region Authentication parameters

        /// <summary>
        /// The byte-length of the session keys for authentication.
        /// </summary>
        public int N_a { get; set; } = 20;

        /// <summary>
        /// The session message authentication key.
        /// </summary>
        public byte[] K_a { get; set; }

        /// <summary>
        /// The byte-length of the output authentication tag.
        /// </summary>
        public int N_tag { get; set; } = 10;

        /// <summary>
        /// SRTP_PREFIX_LENGTH SHALL be zero for HMAC-SHA1.
        /// </summary>
        public int SRTP_PREFIX_LENGTH { get; set; } = 0;

        #endregion // Authentication parameters

        public SRTPContext(int protectionProfile, byte[] mki, byte[] masterKey, byte[] masterSalt, SRTPContextType type)
        {
            this._contextType = type;

            this.ProtectionProfile = protectionProfile;
            this.Mki = mki;
            this.MasterKey = masterKey;
            this.MasterSalt = masterSalt;

            if (SRTProtocol.DTLSProtectionProfiles.TryGetValue(protectionProfile, out SRTPProtectionProfile srtpSecurityParams))
            {
                Cipher = srtpSecurityParams.Cipher;
                Auth = srtpSecurityParams.Auth;
                N_e = srtpSecurityParams.CipherKeyLength >> 3;
                N_a = srtpSecurityParams.AuthKeyLength >> 3;
                N_s = srtpSecurityParams.CipherSaltLength >> 3;
                N_tag = srtpSecurityParams.AuthTagLength >> 3;
                SRTP_PREFIX_LENGTH = srtpSecurityParams.SrtpPrefixLength;
            }
            else
            {
                throw new NotSupportedException($"Protection profile {protectionProfile} is unsupported!");
            }

            DeriveSessionKeys();
        }

        public void DeriveSessionKeys(ulong index = 0)
        {
            int labelBaseValue = _contextType == SRTPContextType.RTP ? 0 : 3;

            if (Cipher == SRTPCiphers.AES_128_CM || Cipher == SRTPCiphers.AES_256_CM || Cipher == SRTPCiphers.NULL)
            {
                var aes = new AesEngine();
                aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                this.K_e = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate); 
                this.K_a = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                this.K_s = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

                aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
                this.AES = aes;
            }
            else if (Cipher == SRTPCiphers.AES_128_F8)
            {
                var aes = new AesEngine();

                // TODO: (!) Assuming the session key is still being derived using AES-CM...
                aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                this.K_e = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                this.K_a = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                this.K_s = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

                aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
                this.AES = aes;

                this.AESF8 = new AesEngine();
            }
            else if (Cipher == SRTPCiphers.AEAD_AES_128_GCM || Cipher == SRTPCiphers.AEAD_AES_256_GCM)
            {
                var aes = new AesEngine();
                aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                this.K_e = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                this.K_a = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                this.K_s = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);
                this.AES = aes;

                var cipher = new GcmBlockCipher(new AesEngine());
                this.AESGCM = cipher;
            }
            else if (Cipher == SRTPCiphers.ARIA_128_CTR || Cipher == SRTPCiphers.ARIA_256_CTR)
            {
                var aria = new AriaEngine();
                aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                this.K_e = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                this.K_a = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                this.K_s = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

                aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
                this.ARIA = aria;
            }
            else if (Cipher == SRTPCiphers.AEAD_ARIA_128_GCM || Cipher == SRTPCiphers.AEAD_ARIA_256_GCM)
            {
                var aria = new AriaEngine();
                aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                this.K_e = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                this.K_a = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                this.K_s = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);
                this.ARIA = aria;

                var cipher = new GcmBlockCipher(new AriaEngine());
                this.ARIAGCM = cipher;
            }
            else
            {
                throw new NotSupportedException($"Unsupported cipher {Cipher.ToString()}!");
            }

            if (Auth == SRTPAuth.HMAC_SHA1)
            {
                var hmac = new HMac(new Sha1Digest());
                hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_a));
                this.HMAC = hmac;
            }
        }

        public static byte[] GenerateSessionKeyAES(AesEngine aes, SRTPCiphers cipher, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] key = new byte[length];
            switch (cipher)
            {
                case SRTPCiphers.NULL:
                case SRTPCiphers.AES_128_CM:
                case SRTPCiphers.AES_128_F8:
                case SRTPCiphers.AES_256_CM:
                case SRTPCiphers.AEAD_AES_128_GCM:
                case SRTPCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = Encryption.AESCM.GenerateSessionKeyIV(masterSalt, index, kdr, (byte)label);
                        Encryption.AESCM.Encrypt(aes, key, 0, length, iv);
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported cipher {cipher.ToString()}!");
            }
            
            return key;
        }

        public static byte[] GenerateSessionKeyARIA(AriaEngine aria, SRTPCiphers cipher, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] key = new byte[length];
            switch (cipher)
            {
                case SRTPCiphers.ARIA_128_CTR:
                case SRTPCiphers.ARIA_256_CTR:
                case SRTPCiphers.AEAD_ARIA_128_GCM:
                case SRTPCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = Encryption.ARIACTR.GenerateSessionKeyIV(masterSalt, index, kdr, (byte)label);
                        Encryption.ARIACTR.Encrypt(aria, key, 0, length, iv);
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported cipher {cipher.ToString()}!");
            }

            return key;
        }

        /// <summary>
        /// Checks and updates the replay window for the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">RTP/RTCP sequence number.</param>
        /// <returns>true if the replay check passed, false when the packed was replayed.</returns>
        /// <remarks>https://datatracker.ietf.org/doc/html/rfc2401 Appendix C</remarks>
        public bool CheckAndUpdateReplayWindow(uint sequenceNumber)
        {
            int diff;

            if (sequenceNumber == 0) return false; /* first == 0 or wrapped */
            if (sequenceNumber > _lastSeq)
            {
                /* new larger sequence number */
                diff = (int)(sequenceNumber - _lastSeq);
                if (diff < REPLAY_WINDOW_SIZE)
                {
                    /* In window */
                    _bitmap = _bitmap << diff;
                    _bitmap |= 1; /* set bit for this packet */
                }
                else _bitmap = 1; /* This packet has a "way larger" */
                _lastSeq = sequenceNumber;
                return true; /* larger is good */
            }
            diff = (int)(_lastSeq - sequenceNumber);
            if (diff >= REPLAY_WINDOW_SIZE) return false; /* too old or wrapped */
            if ((_bitmap & ((ulong)1 << diff)) == ((ulong)1 << diff)) return false; /* already seen */
            _bitmap |= ((ulong)1 << diff); /* mark as seen */
            return true; /* out of order but good */
        }

        /// <summary>
        /// Increments the master key use counter.
        /// </summary>
        public bool IncrementMasterKeyUseCounter()
        {
            long currentValue = Interlocked.Increment(ref _masterKeySentCounter);
            long maxAllowedValue = _contextType == SRTPContextType.RTP ? 281474976710656L : 2147483648L;
            if (currentValue >= maxAllowedValue) // 2^48
            {
                OnRekeyingRequested?.Invoke(this, new EventArgs());

                // at this point we shall not transmit any other packets protected by these keys
                return false;
            }

            return true;
        }
    }
}
