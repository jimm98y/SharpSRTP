using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;

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

        public HMac HMAC { get; private set; }
        public AesEngine AES { get; private set; }

        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public uint S_l { get { return _lastSeq; } set { _lastSeq = value; } }
        public bool S_l_set { get; set; } = false;

        public int ProtectionProfile { get; set; }

        public bool IsMkiPresent { get; set; }
        public int MkiLength { get; set; }

        public byte[] Mki { get; set; }

        public byte[] MasterKey { get; set; }
        public byte[] MasterSalt { get; set; }
        public int MasterKeySentCounter { get; set; }

        /// <summary>
        /// Key derivation rate.
        /// </summary>
        public ulong KeyDerivationRate { get; set; } = 0;

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

        public SRTPContext(int protectionProfile, byte[] masterKey, byte[] masterSalt, SRTPContextType type)
        {
            this._contextType = type;

            this.ProtectionProfile = protectionProfile;
            this.MasterKey = masterKey;
            this.MasterSalt = masterSalt;
            
            DeriveSessionKeys();
        }

        public void DeriveSessionKeys()
        {
            int labelBaseValue = _contextType == SRTPContextType.RTP ? 0 : 3;

            const ulong index = 0;
            this.K_e = SRTPProtocol.GenerateSessionKey(MasterKey, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate); // TODO: use ROC?
            this.K_a = SRTPProtocol.GenerateSessionKey(MasterKey, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
            this.K_s = SRTPProtocol.GenerateSessionKey(MasterKey, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

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
