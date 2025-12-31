// SharpSRTP
// Copyright (C) 2025 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using SharpSRTP.SRTP.Readers;
using System;
using System.Linq;
using System.Threading;

namespace SharpSRTP.SRTP
{
    public enum SrtpContextType
    {
        RTP,
        RTCP
    }

    public class SrtpContext
    {
        private const int REPLAY_WINDOW_SIZE = 64; // Minumum is 64 according to the RFC, our current implmentation is using a bit mask, so it won't allow more than 64.

        private ulong _bitmap = 0; /* session state - must be 32 bits */
        private uint _lastSeq = 0; /* session state */
        private readonly SrtpContextType _contextType;

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

        public SrtpProtectionProfileConfiguration ProtectionProfile { get; set; }
        public SrtpCiphers Cipher { get; set; } = SrtpCiphers.AES_128_CM;
        public SrtpAuth Auth { get; set; } = SrtpAuth.HMAC_SHA1;

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
        public byte[] Mki { get; private set; }

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

        public SrtpContext(SrtpProtectionProfileConfiguration protectionProfile, byte[] mki, byte[] masterKey, byte[] masterSalt, SrtpContextType type)
        {
            this._contextType = type;

            this.ProtectionProfile = protectionProfile ?? throw new ArgumentNullException(nameof(protectionProfile));
            this.Mki = mki ?? new byte[0];
            this.MasterKey = masterKey;
            this.MasterSalt = masterSalt;

            Cipher = protectionProfile.Cipher;
            Auth = protectionProfile.Auth;
            N_e = protectionProfile.CipherKeyLength >> 3;
            N_a = protectionProfile.AuthKeyLength >> 3;
            N_s = protectionProfile.CipherSaltLength >> 3;
            N_tag = protectionProfile.AuthTagLength >> 3;
            SRTP_PREFIX_LENGTH = protectionProfile.SrtpPrefixLength;

            DeriveSessionKeys();
        }

        #region Session key derivation

        public void DeriveSessionKeys(ulong index = 0)
        {
            int labelBaseValue = _contextType == SrtpContextType.RTP ? 0 : 3;

            switch(Cipher)
            {
                case SrtpCiphers.NULL:
                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        var aes = new AesEngine();
                        aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                        this.K_e = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                        this.K_a = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                        this.K_s = GenerateSessionKeyAES(aes, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

                        aes.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
                        this.AES = aes;
                    }
                    break;

                case SrtpCiphers.AES_128_F8:
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
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
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
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        var aria = new AriaEngine();
                        aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(MasterKey));
                        this.K_e = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_e, labelBaseValue + 0, index, KeyDerivationRate);
                        this.K_a = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_a, labelBaseValue + 1, index, KeyDerivationRate);
                        this.K_s = GenerateSessionKeyARIA(aria, Cipher, MasterSalt, N_s, labelBaseValue + 2, index, KeyDerivationRate);

                        aria.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_e));
                        this.ARIA = aria;
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
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
                    break;

                default:
                    throw new NotSupportedException($"Unsupported cipher {Cipher.ToString()}!");

            }

            switch(Auth)
            {
                case SrtpAuth.NONE:
                    break;

                case SrtpAuth.HMAC_SHA1:
                    {
                        var hmac = new HMac(new Sha1Digest());
                        hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(K_a));
                        this.HMAC = hmac;
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported auth {Auth.ToString()}!");
            }
        }

        public static byte[] GenerateSessionKeyAES(AesEngine aes, SrtpCiphers cipher, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] key = new byte[length];
            switch (cipher)
            {
                case SrtpCiphers.NULL:
                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_128_F8:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
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

        public static byte[] GenerateSessionKeyARIA(AriaEngine aria, SrtpCiphers cipher, byte[] masterSalt, int length, int label, ulong index, ulong kdr)
        {
            byte[] key = new byte[length];
            switch (cipher)
            {
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
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

        #endregion // Session key derivation

        #region Encryption

        public const uint E_FLAG = 0x80000000;

        public const int ERROR_GENERIC = -1;
        public const int ERROR_UNSUPPORTED_CIPHER = -2;
        public const int ERROR_HMAC_CHECK_FAILED = -3;
        public const int ERROR_REPLAY_CHECK_FAILED = -4;
        public const int ERROR_MASTER_KEY_ROTATION_REQUIRED = -5;
        public const int ERROR_MKI_CHECK_FAILED = -6;

        public int ProtectRtp(byte[] payload, int length, out int outputBufferLength)
        {
            var context = this;
            outputBufferLength = length;

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);
            int offset = RtpReader.ReadHeaderLen(payload);

            uint roc = context.Roc;
            ulong index = SrtpContext.GenerateRtpIndex(roc, sequenceNumber);

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESF8.GenerateRtpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        SharpSRTP.SRTP.Encryption.AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        SharpSRTP.SRTP.Encryption.AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        SharpSRTP.SRTP.Encryption.AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        SharpSRTP.SRTP.Encryption.ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        SharpSRTP.SRTP.Encryption.ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                default:
                    return ERROR_UNSUPPORTED_CIPHER;
            }

            byte[] mki = context.Mki;
            if (mki.Length > 0)
            {
                Buffer.BlockCopy(mki, 0, payload, length, mki.Length);
                length += mki.Length;
                outputBufferLength += mki.Length;
            }

            if (context.Auth != SrtpAuth.NONE)
            {
                payload[length + 0] = (byte)(roc >> 24);
                payload[length + 1] = (byte)(roc >> 16);
                payload[length + 2] = (byte)(roc >> 8);
                payload[length + 3] = (byte)roc;

                byte[] auth = SharpSRTP.SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, payload, 0, length + 4);
                System.Buffer.BlockCopy(auth, 0, payload, length, context.N_tag); // we don't append ROC in SRTP
                length += context.N_tag;
                outputBufferLength += context.N_tag;
            }

            // TODO: review
            if (sequenceNumber == 0xFFFF)
            {
                context.Roc++;
            }

            return 0;
        }

        public int UnprotectRtp(byte[] payload, int length, out int outputBufferLength)
        {
            var context = this;

            byte[] mki = context.Mki;
            outputBufferLength = length - context.N_tag - mki.Length;

            for (int i = 0; i < mki.Length; i++)
            {
                if (payload[length - context.N_tag - mki.Length + i] != mki[i])
                    return ERROR_MKI_CHECK_FAILED;
            }

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);

            if (context.Auth != SrtpAuth.NONE)
            {
                // TODO: optimize memory allocation - we could preallocate 4 byte array and add another GenerateAuthTag overload that processes 2 blocks
                int authenticatedLen = length - context.N_tag - mki.Length;
                byte[] msgAuth = new byte[authenticatedLen + 4];
                Buffer.BlockCopy(payload, 0, msgAuth, 0, msgAuth.Length);
                msgAuth[authenticatedLen + 0] = (byte)(context.Roc >> 24);
                msgAuth[authenticatedLen + 1] = (byte)(context.Roc >> 16);
                msgAuth[authenticatedLen + 2] = (byte)(context.Roc >> 8);
                msgAuth[authenticatedLen + 3] = (byte)(context.Roc);

                byte[] auth = SharpSRTP.SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, msgAuth, 0, authenticatedLen + 4);
                for (int i = 0; i < context.N_tag; i++)
                {
                    if (payload[length - context.N_tag + i] != auth[i])
                    {
                        return ERROR_HMAC_CHECK_FAILED;
                    }
                }

                msgAuth = null;
            }

            if (!context.S_l_set)
            {
                context.S_l = sequenceNumber;
                context.S_l_set = true;
            }

            int offset = RtpReader.ReadHeaderLen(payload);
            uint roc = context.Roc;
            uint index = SrtpContext.DetermineRtpIndex(context.S_l, sequenceNumber, roc);

            if (!context.CheckAndUpdateReplayWindow(index))
            {
                return ERROR_REPLAY_CHECK_FAILED;
            }

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESF8.GenerateRtpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        SharpSRTP.SRTP.Encryption.AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        SharpSRTP.SRTP.Encryption.AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        SharpSRTP.SRTP.Encryption.AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        SharpSRTP.SRTP.Encryption.ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        SharpSRTP.SRTP.Encryption.ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                    }
                    break;

                default:
                    return ERROR_UNSUPPORTED_CIPHER;
            }

            return 0;
        }

        public int ProtectRtcp(byte[] payload, int length, out int outputBufferLength)
        {
            var context = this;
            outputBufferLength = length;

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RtcpReader.ReadSsrc(payload);
            int offset = RtcpReader.GetHeaderLen();
            uint index = context.S_l | E_FLAG;

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESF8.GenerateRtcpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                        SharpSRTP.SRTP.Encryption.AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        SharpSRTP.SRTP.Encryption.AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        byte[] associatedData = payload.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
                        SharpSRTP.SRTP.Encryption.AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        SharpSRTP.SRTP.Encryption.ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = SharpSRTP.SRTP.Encryption.ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        byte[] associatedData = payload.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
                        SharpSRTP.SRTP.Encryption.ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                default:
                    return ERROR_UNSUPPORTED_CIPHER;
            }

            payload[length + 0] = (byte)(index >> 24);
            payload[length + 1] = (byte)(index >> 16);
            payload[length + 2] = (byte)(index >> 8);
            payload[length + 3] = (byte)index;
            outputBufferLength += 4;
            length += 4;

            byte[] mki = context.Mki;
            if (mki.Length > 0)
            {
                Buffer.BlockCopy(mki, 0, payload, length, mki.Length);
                length += mki.Length;
                outputBufferLength += mki.Length;
            }

            if (context.Auth != SrtpAuth.NONE)
            {
                byte[] auth = SharpSRTP.SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, payload, 0, length);
                System.Buffer.BlockCopy(auth, 0, payload, length, context.N_tag);
                length += context.N_tag;
                outputBufferLength += context.N_tag;
            }

            context.S_l = (context.S_l + 1) % 0x80000000;

            return 0;
        }

        public int UnprotectRtcp(byte[] payload, int length, out int outputBufferLength)
        {
            var context = this;

            byte[] mki = context.Mki;
            outputBufferLength = length - 4 - context.N_tag - mki.Length;

            for (int i = 0; i < mki.Length; i++)
            {
                if (payload[length - context.N_tag - mki.Length + i] != mki[i])
                    return ERROR_MKI_CHECK_FAILED;
            }

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RtcpReader.ReadSsrc(payload);
            int offset = RtcpReader.GetHeaderLen();
            uint index = RtcpReader.SrtcpReadIndex(payload, context.N_a > 0 ? (context.N_tag + mki.Length) : 0);
            bool isEncrypted = false;

            if ((index & E_FLAG) == E_FLAG)
            {
                index = index & ~E_FLAG;
                isEncrypted = true;
            }

            if (context.Auth != SrtpAuth.NONE)
            {
                byte[] auth = SharpSRTP.SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, payload, 0, length - context.N_tag - mki.Length);
                for (int i = 0; i < context.N_tag; i++)
                {
                    if (payload[length - context.N_tag + i] != auth[i])
                    {
                        return ERROR_HMAC_CHECK_FAILED;
                    }
                }
            }

            if (!context.CheckAndUpdateReplayWindow(index))
            {
                return ERROR_REPLAY_CHECK_FAILED;
            }

            if (isEncrypted)
            {
                switch (context.Cipher)
                {
                    case SrtpCiphers.NULL:
                        break;

                    case SrtpCiphers.AES_128_F8:
                        {
                            byte[] iv = SharpSRTP.SRTP.Encryption.AESF8.GenerateRtcpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                            SharpSRTP.SRTP.Encryption.AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AES_128_CM:
                    case SrtpCiphers.AES_192_CM:
                    case SrtpCiphers.AES_256_CM:
                        {
                            byte[] iv = SharpSRTP.SRTP.Encryption.AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            SharpSRTP.SRTP.Encryption.AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AEAD_AES_128_GCM:
                    case SrtpCiphers.AEAD_AES_256_GCM:
                        {
                            byte[] iv = SharpSRTP.SRTP.Encryption.AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            byte[] associatedData = payload.Take(offset).Concat(payload.Skip(length - 4).Take(4)).ToArray(); // associatedData include also index
                            SharpSRTP.SRTP.Encryption.AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                        }
                        break;

                    case SrtpCiphers.ARIA_128_CTR:
                    case SrtpCiphers.ARIA_256_CTR:
                        {
                            byte[] iv = SharpSRTP.SRTP.Encryption.ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            SharpSRTP.SRTP.Encryption.ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AEAD_ARIA_128_GCM:
                    case SrtpCiphers.AEAD_ARIA_256_GCM:
                        {
                            byte[] iv = SharpSRTP.SRTP.Encryption.ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            byte[] associatedData = payload.Take(offset).Concat(payload.Skip(length - 4).Take(4)).ToArray(); // associatedData include also index
                            SharpSRTP.SRTP.Encryption.ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                        }
                        break;

                    default:
                        return ERROR_UNSUPPORTED_CIPHER;
                }
            }

            return 0;
        }

        public static uint DetermineRtpIndex(uint s_l, ushort SEQ, ulong ROC)
        {
            // RFC 3711 - Appendix A
            ulong v;
            if (s_l < 32768)
            {
                if (SEQ - s_l > 32768)
                    v = (ROC - 1) % 4294967296L;
                else
                    v = ROC;
            }
            else
            {
                if (s_l - 32768 > SEQ)
                    v = (ROC + 1) % 4294967296L;
                else
                    v = ROC;
            }
            return (uint)(SEQ + v * 65536U);
        }

        public static ulong GenerateRtpIndex(uint ROC, ushort SEQ)
        {
            // RFC 3711 - 3.3.1
            // i = 2 ^ 16 * ROC + SEQ
            return ((ulong)ROC << 16) | SEQ;
        }

        #endregion // Encryption

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
            long maxAllowedValue = _contextType == SrtpContextType.RTP ? 281474976710656L : 2147483648L;
            if (currentValue >= maxAllowedValue)
            {
                OnRekeyingRequested?.Invoke(this, new EventArgs());

                // at this point we shall not transmit any other packets protected by these keys
                return false;
            }

            return true;
        }
    }
}
