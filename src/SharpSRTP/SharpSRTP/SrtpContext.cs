using System;
using System.Collections.Generic;

namespace SharpSRTP.SRTP
{
    public class SrtpContext
    {
        private readonly bool _isRtp;

        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public uint S_l { get; set; } = 0;

        public int Cipher { get; set; }
        public int Authentication { get; set; }

        /// <summary>
        /// Receiver only - list of recently received sequence numbers for replay protection.
        /// </summary>
        public List<ushort> ReplayList { get; set; }

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
        /// The length of the session keys for encryption.
        /// </summary>
        public uint N_e { get; set; } = 128;

        /// <summary>
        /// Session key for encryption.
        /// </summary>
        public byte[] K_e { get; set; }

        /// <summary>
        /// The bit-length of k_s.
        /// </summary>
        public uint N_s { get; set; }

        /// <summary>
        /// Session salting key.
        /// </summary>
        public byte[] K_s { get; set; }

        #endregion // Session key parameters

        #region Authentication parameters

        /// <summary>
        /// The length of the session keys for authentication.
        /// </summary>
        public uint N_a { get; set; } = 160;

        /// <summary>
        /// The session message authentication key.
        /// </summary>
        public byte[] K_a { get; set; }

        /// <summary>
        /// The bit-length of the output authentication tag.
        /// </summary>
        public int N_tag { get; set; } = 80;

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

        public void DeriveSessionKeys(int counter = 0)
        {
            int b = _isRtp ? 0 : 3;
            this.K_e = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, b + 0, counter); // TODO: use ROC?
            this.K_a = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, b + 1, counter);
            this.K_s = SrtpKeyGenerator.GenerateSessionKey(MasterKey, MasterSalt, b + 2, counter);
        }
    }
}
