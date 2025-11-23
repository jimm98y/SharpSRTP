using System;
using System.Collections.Generic;
using System.Text;

namespace DtlsServerSample.SRTP
{
    public class SrtpContext
    {
        /// <summary>
        /// Rollover counter.
        /// </summary>
        public uint Roc { get; set; } = 0;

        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public ushort S_l { get; set; } = 0;

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
        /// The length of the session keys for encryption.
        /// </summary>
        public uint N_e { get; set; }



        /// <summary>
        /// Key derivation rate.
        /// </summary>
        public int KeyDerivationRate { get; set; } = 0;

        /// <summary>
        /// From, To values, specifying the lifetime for a master key.
        /// </summary>
        public int From { get; set; }
        public int To { get; set; }


        #region Authentication parameters

        /// <summary>
        /// The session message authentication key.
        /// </summary>
        public byte[] K_a { get; set; }

        /// <summary>
        /// The length of the session keys for authentication.
        /// </summary>
        public uint N_a { get; set; } = 160;

        /// <summary>
        /// The bit-length of the output authentication tag.
        /// </summary>
        public int N_tag { get; set; } = 80;

        /// <summary>
        /// SRTP_PREFIX_LENGTH SHALL be zero for HMAC-SHA1.
        /// </summary>
        public int SRTP_PREFIX_LENGTH { get; set; } = 0;

        #endregion // Authentication parameters

        public SrtpContext()
        {
            
        }


    }
}
