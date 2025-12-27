using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;

namespace SharpSRTP.SRTP
{
    public class SrtpContext
    {
        private const int REPLAY_WINDOW_SIZE = 64;

        private ulong _bitmap = 0; /* session state - must be 32 bits */
        private uint _lastSeq = 0; /* session state */
        private readonly bool _isRtp;

        public HMac HMAC { get; private set; }
        public AesEngine AES { get; private set; }


        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public uint S_l { get { return _lastSeq; } set { _lastSeq = value; } }
        public bool S_l_set { get; set; } = false;

        public int Cipher { get; set; }
        public int Authentication { get; set; }


        public bool IsMkiPresent { get; set; }

        public int MkiLength { get; set; }

        public byte[] Mki { get; set; }

        public byte[] MasterKey { get; set; }
        public byte[] MasterSalt { get; set; }
        public int MasterKeySentCounter { get; set; }


        /// <summary>
        /// Key derivation rate.
        /// </summary>
        public int KeyDerivationRate { get; set; } = 0;

        /// <summary>
        /// From, To values, specifying the lifetime for a master key.
        /// </summary>
        public int From { get; set; }
        public int To { get; set; }

        /// <summary>
        /// Rollover counter.
        /// </summary>
        public uint Roc { get; set; } = 0;

        #region Session key parameters

        /// <summary>
        /// The byte-length of the session keys for encryption.
        /// </summary>
        public uint N_e { get; set; } = 16;

        /// <summary>
        /// Session key for encryption.
        /// </summary>
        public byte[] K_e { get; set; }

        /// <summary>
        /// The byte-length of k_s.
        /// </summary>
        public uint N_s { get; set; } = 14;

        /// <summary>
        /// Session salting key.
        /// </summary>
        public byte[] K_s { get; set; }

        #endregion // Session key parameters

        #region Authentication parameters

        /// <summary>
        /// The byte-length of the session keys for authentication.
        /// </summary>
        public uint N_a { get; set; } = 20;

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

        public SrtpContext(byte[] masterKey, byte[] masterSalt, bool isRtp)
        {
            this._isRtp = isRtp;

            this.MasterKey = masterKey;
            this.MasterSalt = masterSalt;
            
            DeriveSessionKeys();
        }

        public void DeriveSessionKeys()
        {
            int b = _isRtp ? 0 : 3;
            this.K_e = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, (int)N_e, b + 0, 0, 0); // TODO: use ROC?
            this.K_a = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, (int)N_a, b + 1, 0, 0);
            this.K_s = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, (int)N_s, b + 2, 0, 0);

            var aes = new AesEngine();
            aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
            this.AES = aes;

            var hmac = new HMac(new Sha1Digest());
            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_a));
            this.HMAC = hmac;
        }

        // https://datatracker.ietf.org/doc/html/rfc2401 Appendix C
        public bool CheckandUpdateReplayWindow(uint seq)
        {
            int diff;

            if (seq == 0) return false; /* first == 0 or wrapped */
            if (seq > _lastSeq)
            {
                /* new larger sequence number */
                diff = (int)(seq - _lastSeq);
                if (diff < REPLAY_WINDOW_SIZE)
                {
                    /* In window */
                    _bitmap = _bitmap << diff;
                    _bitmap |= 1; /* set bit for this packet */
                }
                else _bitmap = 1; /* This packet has a "way larger" */
                _lastSeq = seq;
                return true; /* larger is good */
            }
            diff = (int)(_lastSeq - seq);
            if (diff >= REPLAY_WINDOW_SIZE) return false; /* too old or wrapped */
            if ((_bitmap & ((ulong)1 << diff)) == ((ulong)1 << diff)) return false; /* already seen */
            _bitmap |= ((ulong)1 << diff); /* mark as seen */
            return true; /* out of order but good */
        }
    }
}
