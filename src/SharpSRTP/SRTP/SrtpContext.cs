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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using SharpSRTP.SRTP.Readers;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Security.Cryptography;
using SharpSRTP;


#if NET8_0_OR_GREATER
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
using Bytes = System.Span<byte>;
#else
using ReadOnlyBytes = byte[];
using Bytes = byte[];
#endif

namespace SharpSRTP.SRTP
{
    public enum SrtpContextType
    {
        RTP,
        RTCP
    }

    public class SsrcSrtpContext
    {
        public const int REPLAY_WINDOW_SIZE = 64; // Minumum is 64 according to the RFC, our current implmentation is using a bit mask, so it won't allow more than 64.

        public ulong Bitmap { get; private set; } = 0;
        public bool LastSeqSet { get; private set; } = false;

        /// <summary>
        /// Receiver only - highest sequence number received.
        /// </summary>
        public uint S_l { get; private set; }
        public bool S_l_set { get; private set; } = false;

        /// <summary>
        /// Checks and updates the replay window for the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">RTP/RTCP sequence number.</param>
        /// <returns>true if the replay check passed, false when the packed was replayed.</returns>
        /// <remarks>https://datatracker.ietf.org/doc/html/rfc2401 Appendix C</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool CheckAndUpdateReplayWindow(uint sequenceNumber)
        {
            int diff;

            if (sequenceNumber == 0)
            {
                if (!S_l_set)
                {
                    S_l_set = true;
                    return true; /* first is good */
                }
                return false; /* first == 0 or wrapped */
            }
            if (sequenceNumber > S_l)
            {
                /* new larger sequence number */
                diff = (int)(sequenceNumber - S_l);
                if (diff < REPLAY_WINDOW_SIZE)
                {
                    /* In window */
                    Bitmap = Bitmap << diff;
                    Bitmap |= 1; /* set bit for this packet */
                }
                else
                {
                    Bitmap = 1; /* This packet has a "way larger" */
                }
                S_l = sequenceNumber;
                return true; /* larger is good */
            }
            diff = (int)(S_l - sequenceNumber);
            if (diff >= REPLAY_WINDOW_SIZE)
            {
                return false; /* too old or wrapped */
            }
            if ((Bitmap & ((ulong)1 << diff)) == ((ulong)1 << diff))
            {
                return false; /* already seen */
            }
            Bitmap |= ((ulong)1 << diff); /* mark as seen */
            return true; /* out of order but good */
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void SetInitialSequence(uint sequenceNumber)
        {
            if (!S_l_set)
            {
                S_l = sequenceNumber;
                S_l_set = true;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void SetSequence(uint sequenceNumber)
        {
            S_l = sequenceNumber;
            S_l_set = true;
        }
    }

    /// <summary>
    /// SRTP context used for protecting/unprotecting RTP/RTCP packets as defined in RFC 3711.
    /// </summary>
    public class SrtpContext : ISrtpContext
    {
        public Dictionary<uint, SsrcSrtpContext> ReplayProtection { get; } = new Dictionary<uint, SsrcSrtpContext>();

        public const int ERROR_GENERIC = -1;
        public const int ERROR_UNSUPPORTED_CIPHER = -2;
        public const int ERROR_HMAC_CHECK_FAILED = -3;
        public const int ERROR_REPLAY_CHECK_FAILED = -4;
        public const int ERROR_MASTER_KEY_ROTATION_REQUIRED = -5;
        public const int ERROR_MKI_CHECK_FAILED = -6;

        public const uint E_FLAG = 0x80000000;

        private readonly SrtpContextType _contextType;
        public SrtpContextType ContextType { get { return _contextType; } }

        public event EventHandler<EventArgs> OnRekeyingRequested;

        public HMac HMAC { get; private set; }
        public IBlockCipher PayloadCTR { get; private set; }
        public IBlockCipher PayloadF8 { get; private set; }
        public IAeadBlockCipher PayloadAEAD { get; private set; }

        public IBlockCipher HeaderCTR { get; private set; }
        public IBlockCipher HeaderF8 { get; private set; }

        public SrtpProtectionProfileConfiguration ProtectionProfile { get; set; }
        public SrtpCiphers Cipher { get; set; }
        public SrtpAuth Auth { get; set; }

        public ReadOnlyMemory<byte> MasterKey { get; set; }
        public ReadOnlyMemory<byte> MasterSalt { get; set; }

        /// <summary>
        /// Rollover counter.
        /// </summary>
        public uint Roc { get; set; } = 0;

        private long _masterKeySentCounter = 0;

        /// <summary>
        /// Specified how many times was the current master key used.
        /// </summary>
        public long MasterKeySentCounter { get { return _masterKeySentCounter; } }

        /// <summary>
        /// Key derivation rate.
        /// </summary>
        public ulong KeyDerivationRate { get; set; }

        /// <summary>
        /// From, To values, specifying the lifetime for a master key.
        /// </summary>
        //public int From { get; set; }
        //public int To { get; set; }

        /// <summary>
        /// Master Key Identifier.
        /// </summary>
        public ReadOnlyMemory<byte> Mki { get; private set; }

        /// <summary>
        /// The byte-length of the session keys for encryption.
        /// </summary>
        public int N_e { get; set; }

        /// <summary>
        /// Session key for encryption.
        /// </summary>
        public ReadOnlyMemory<byte> K_e { get; set; }

        /// <summary>
        /// The byte-length of k_s.
        /// </summary>
        public int N_s { get; set; }

        /// <summary>
        /// Session salting key.
        /// </summary>
        public ReadOnlyMemory<byte> K_s { get; set; }

        /// <summary>
        /// Session key for RTP header encyption. Not used in RTCP.
        /// </summary>
        public ReadOnlyMemory<byte> K_he { get; set; }

        /// <summary>
        /// Session salt for header encryption.
        /// </summary>
        public ReadOnlyMemory<byte> K_hs { get; set; }

        /// <summary>
        /// Gets or sets the encryption mask applied to RTP header extensions.
        /// </summary>
        /// <remarks>The encryption mask is used to protect the contents of RTP header extensions. If set to empty, header extensions will not be encrypted.</remarks>
        public ReadOnlyMemory<byte> RtpHeaderExtensionsEncryptionMask { get; set; }

        /// <summary>
        /// The byte-length of the session keys for authentication.
        /// </summary>
        public int N_a { get; set; }

        /// <summary>
        /// The session message authentication key.
        /// </summary>
        public ReadOnlyMemory<byte> K_a { get; set; }

        /// <summary>
        /// The byte-length of the output authentication tag.
        /// </summary>
        public int N_tag { get; set; }

        /// <summary>
        /// SRTP_PREFIX_LENGTH SHALL be zero for HMAC-SHA1.
        /// </summary>
        public int SRTP_PREFIX_LENGTH { get; set; } = 0;

        public SrtpContext(
            SrtpContextType contextType,
            SrtpProtectionProfileConfiguration protectionProfile,
            ReadOnlyMemory<byte> masterKey,
            ReadOnlyMemory<byte> masterSalt,
            ReadOnlyMemory<byte> mki = default)
        {
            Throw.IfNull(protectionProfile);

            this._contextType = contextType;
            this.ProtectionProfile = protectionProfile;
            if (masterKey.IsEmpty) Throw.ArgumentException($"{nameof(masterKey)} cannot be empty.", nameof(masterKey));
            if (masterSalt.IsEmpty) Throw.ArgumentException($"{nameof(masterSalt)} cannot be empty.", nameof(masterSalt));
            this.MasterKey = masterKey;
            this.MasterSalt = masterSalt;
            this.Mki = mki.Length > 0 ? mki : ReadOnlyMemory<byte>.Empty;

            Cipher = protectionProfile.Cipher;
            Auth = protectionProfile.Auth;
            N_e = protectionProfile.CipherKeyLength >> 3;
            N_a = protectionProfile.AuthKeyLength >> 3;
            N_s = protectionProfile.CipherSaltLength >> 3;
            N_tag = protectionProfile.AuthTagLength >> 3;
            SRTP_PREFIX_LENGTH = protectionProfile.SrtpPrefixLength;

            DeriveSessionKeys();
        }

        public virtual void DeriveSessionKeys(ulong index = 0)
        {
            int labelBaseValue = _contextType == SrtpContextType.RTP ? 0 : 3;

            switch (Cipher)
            {
                case SrtpCiphers.NULL:
                case SrtpCiphers.AES_128_F8:
                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        var aesKeys = new AesEngine();
                        var k_e = new byte[N_e];
                        GenerateSessionKey(k_e, aesKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 0, index, KeyDerivationRate);
                        this.K_e = k_e;
                        var k_a = new byte[N_a];
                        GenerateSessionKey(k_a, aesKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 1, index, KeyDerivationRate);
                        this.K_a = k_a;
                        var k_s = new byte[N_s];
                        GenerateSessionKey(k_s, aesKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 2, index, KeyDerivationRate);
                        this.K_s = k_s;
                        var k_he = new byte[N_e];
                        GenerateSessionKey(k_he, aesKeys, Cipher, MasterKey.Span, MasterSalt.Span, 6, index, KeyDerivationRate);
                        this.K_he = k_he;
                        var k_hs = new byte[N_s];
                        GenerateSessionKey(k_hs, aesKeys, Cipher, MasterKey.Span, MasterSalt.Span, 7, index, KeyDerivationRate);
                        this.K_hs = k_hs;

                        if (Cipher >= SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM)
                        {
                            var outerK_e = K_e.Slice(K_e.Length / 2);
                            var outerK_he = K_he.Slice(K_he.Length / 2);

                            var aesPayload = new AesEngine();
                            aesPayload.Init(true, outerK_e.ToKeyParameter());
                            this.PayloadCTR = aesPayload;

                            var aesHeader = new AesEngine();
                            aesHeader.Init(true, outerK_he.ToKeyParameter());
                            this.HeaderCTR = aesHeader;
                        }
                        else
                        {
                            var aesPayload = new AesEngine();
                            aesPayload.Init(true, K_e.ToKeyParameter());
                            this.PayloadCTR = aesPayload;

                            var aesHeader = new AesEngine();
                            aesHeader.Init(true, K_he.ToKeyParameter());
                            this.HeaderCTR = aesHeader;
                        }

                        if (Cipher == SrtpCiphers.AES_128_F8)
                        {
                            this.PayloadF8 = new AesEngine();
                            this.HeaderF8 = new AesEngine();
                        }
                        else if (Cipher == SrtpCiphers.AEAD_AES_128_GCM || Cipher == SrtpCiphers.AEAD_AES_256_GCM)
                        {
                            this.PayloadAEAD = new GcmBlockCipher(new AesEngine());
                        }
                        else if (Cipher == SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM || Cipher == SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM)
                        {
                            this.PayloadAEAD = new GcmBlockCipher(new AesEngine());
                        }
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        var ariaKeys = new AriaEngine();
                        var k_e = new byte[N_e];
                        GenerateSessionKey(k_e, ariaKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 0, index, KeyDerivationRate);
                        this.K_e = k_e;
                        var k_a = new byte[N_a];
                        GenerateSessionKey(k_a, ariaKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 1, index, KeyDerivationRate);
                        this.K_a = k_a;
                        var k_s = new byte[N_s];
                        GenerateSessionKey(k_s, ariaKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 2, index, KeyDerivationRate);
                        this.K_s = k_s;
                        var k_he = new byte[N_e];
                        GenerateSessionKey(k_he, ariaKeys, Cipher, MasterKey.Span, MasterSalt.Span, 6, index, KeyDerivationRate);
                        this.K_he = k_he;
                        var k_hs = new byte[N_s];
                        GenerateSessionKey(k_hs, ariaKeys, Cipher, MasterKey.Span, MasterSalt.Span, 7, index, KeyDerivationRate);
                        this.K_hs = k_hs;

                        var ariaPayload = new AriaEngine();
                        ariaPayload.Init(true, K_e.ToKeyParameter());
                        this.PayloadCTR = ariaPayload;

                        var ariaHeader = new AriaEngine();
                        ariaHeader.Init(true, K_he.ToKeyParameter());
                        this.HeaderCTR = ariaHeader;

                        if (Cipher == SrtpCiphers.AEAD_ARIA_128_GCM || Cipher == SrtpCiphers.AEAD_ARIA_256_GCM)
                        {
                            this.PayloadAEAD = new GcmBlockCipher(new AriaEngine());
                        }
                    }
                    break;

                case SrtpCiphers.SEED_128_CTR:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
                        var seedKeys = new SeedEngine();
                        var k_e = new byte[N_e];
                        GenerateSessionKey(k_e, seedKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 0, index, KeyDerivationRate);
                        this.K_e = k_e;
                        var k_a = new byte[N_a];
                        GenerateSessionKey(k_a, seedKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 1, index, KeyDerivationRate);
                        this.K_a = k_a;
                        var k_s = new byte[N_s];
                        GenerateSessionKey(k_s, seedKeys, Cipher, MasterKey.Span, MasterSalt.Span, labelBaseValue + 2, index, KeyDerivationRate);
                        this.K_s = k_s;
                        var k_he = new byte[N_e];
                        GenerateSessionKey(k_he, seedKeys, Cipher, MasterKey.Span, MasterSalt.Span, 6, index, KeyDerivationRate);
                        this.K_he = k_he;
                        var k_hs = new byte[N_s];
                        GenerateSessionKey(k_hs, seedKeys, Cipher, MasterKey.Span, MasterSalt.Span, 7, index, KeyDerivationRate);
                        this.K_hs = k_hs;

                        var seedPayload = new SeedEngine();
                        seedPayload.Init(true, K_e.ToKeyParameter());
                        this.PayloadCTR = seedPayload;

                        var seedHeader = new AriaEngine();
                        seedHeader.Init(true, K_he.ToKeyParameter());
                        this.HeaderCTR = seedHeader;

                        if (Cipher == SrtpCiphers.SEED_128_CCM)
                        {
                            this.PayloadAEAD = new CcmBlockCipher(new SeedEngine());
                        }
                        else if (Cipher == SrtpCiphers.SEED_128_GCM)
                        {
                            this.PayloadAEAD = new GcmBlockCipher(new SeedEngine());
                        }
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported cipher {Cipher.ToString()}!");

            }

            switch (Auth)
            {
                case SrtpAuth.NONE:
                    break;

                case SrtpAuth.HMAC_SHA1:
                    {
                        var hmac = new HMac(new Sha1Digest());
                        hmac.Init(K_a.ToKeyParameter());
                        this.HMAC = hmac;
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported auth {Auth.ToString()}!");
            }
        }

        public static void GenerateSessionKey(Span<byte> key, IBlockCipher engineKeys, SrtpCiphers cipher, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> masterSalt, int label, ulong index, ulong kdr)
        {
            switch (cipher)
            {
                case SrtpCiphers.NULL:
                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_128_F8:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                case SrtpCiphers.SEED_128_CTR:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
                        engineKeys.Init(true, new KeyParameter(masterKey.ToArray()));
                        Span<byte> iv = stackalloc byte[Encryption.CTR.BLOCK_SIZE];
                        Encryption.CTR.GenerateSessionKeyIV(iv, masterSalt, index, kdr, (byte)label);
                        Encryption.CTR.Encrypt(key, engineKeys, key, iv);
                    }
                    break;

                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        var innerSalt = masterSalt.Slice(0, masterSalt.Length / 2);
                        var innerKey = masterKey.Slice(0, masterKey.Length / 2);
                        Span<byte> innerIv = stackalloc byte[Encryption.CTR.BLOCK_SIZE];
                        Encryption.CTR.GenerateSessionKeyIV(innerIv, innerSalt, index, kdr, (byte)label);
                        engineKeys.Init(true, new KeyParameter(innerKey.AsBytes()));
                        var key1 = key.Slice(0, key.Length / 2);
                        Encryption.CTR.Encrypt(key1, engineKeys, key1, innerIv);

                        var outerSalt = masterSalt.Slice(masterSalt.Length / 2);
                        var outerKey = masterKey.Slice(masterKey.Length / 2);
                        Span<byte> outerIv = stackalloc byte[Encryption.CTR.BLOCK_SIZE];
                        Encryption.CTR.GenerateSessionKeyIV(outerIv, outerSalt, index, kdr, (byte)label);
                        engineKeys.Init(true, new KeyParameter(outerKey.AsBytes()));
                        var key2 = key.Slice(key.Length / 2);
                        Encryption.CTR.Encrypt(key2, engineKeys, key2, outerIv);
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unsupported cipher {cipher}!");
            }
        }

        public virtual int CalculateRequiredSrtpPayloadLength(int rtpLen)
        {
            var context = this;
            var mki = context.Mki;
            return rtpLen + mki.Length + context.N_tag + (Cipher >= SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM ? 1 : 0);
        }

        [SkipLocalsInit]
        public int ProtectRtp(Span<byte> output, ReadOnlySpan<byte> payload)
        {
            var context = this;

            Throw.IfLessThan(output.Length, CalculateRequiredSrtpPayloadLength(payload.Length));

            if (!context.IncrementMasterKeyUseCounter())
            {
                Throw.CryptographicException(ERROR_MASTER_KEY_ROTATION_REQUIRED);
            }

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);
            int offset = RtpReader.ReadHeaderLen(payload);
            uint roc = context.Roc;
            ulong index = SrtpContext.GenerateRtpIndex(roc, sequenceNumber);

            int outputBufferLength = payload.Length;
            payload.Slice(0, offset).CopyTo(output);

            // RFC6904
            var rtpExtensionsMask = RtpHeaderExtensionsEncryptionMask;
            if (!rtpExtensionsMask.IsEmpty)
            {
                int rtpExtensionsOffset = RtpReader.ReadHeaderLenWithoutExtensions(payload) + 4; // 4 bytes of "defined by profile" and "length" fields
                if (RtpReader.ReadExtensionsLength(payload) <= 0)
                {
                    Throw.InvalidOperationException("RTP header extensions encryption mask is set, but the RTP packet does not contain any header extensions!");
                }

                var rtpExtensions = RtpReader.ReadHeaderExtensions(payload);
                Span<byte> rtpExtensionsOutput = stackalloc byte[rtpExtensions.Length];
                ProtectUnprotectRtpHeaderExtensions(rtpExtensionsOutput, payload, rtpExtensions, rtpExtensionsMask.Span, ssrc, roc, index);
                rtpExtensionsOutput.CopyTo(output.Slice(rtpExtensionsOffset, rtpExtensions.Length));
            }

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    payload.CopyTo(output);
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.F8.GenerateRtpMessageKeyIV(iv, context.PayloadF8, context.K_e.Span, context.K_s.Span, payload, roc);
                        var payloadSpan = output.Slice(offset, payload.Length - offset);
                        SRTP.Encryption.F8.Encrypt(payloadSpan, context.PayloadCTR, payload.Slice(offset), iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.SEED_128_CTR:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.CTR.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.CTR.BLOCK_SIZE);
#endif
                        SRTP.Encryption.CTR.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, index);
                        var payloadSpan = output.Slice(offset, payload.Length - offset);
                        SRTP.Encryption.CTR.Encrypt(payloadSpan, context.PayloadCTR, payload.Slice(offset), iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
                        byte[] iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, index);
                        var associatedData = payload.Slice(0, offset).ToArray();
                        var inputSpan = payload.Slice(offset);
                        var outputSpan = output.Slice(offset, payload.Length - offset + context.N_tag);
                        SRTP.Encryption.AEAD.Encrypt(outputSpan, context.PayloadAEAD, true, inputSpan, iv, context.K_e, context.N_tag, associatedData);
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        // form a synthetic RTP packet
                        var rtpHeaderLength = RtpReader.ReadHeaderLenWithoutExtensions(payload);
                        var rtpExtensionsLength = RtpReader.ReadExtensionsLength(payload);
                        var halfContextNTag = context.N_tag / 2;
                        var halfContextKELength = context.K_e.Length / 2;
                        var halfContextKSLength = context.K_s.Length / 2;

                        var syntheticRtpPacketLength = payload.Length - rtpExtensionsLength + halfContextNTag;
                        var rentedBuffer = ArrayPool<byte>.Shared.Rent(syntheticRtpPacketLength);
                        try
                        {
                            var syntheticRtpPacket = rentedBuffer.AsSpan(0, syntheticRtpPacketLength);

                            // copy header without extensions
                            payload.Slice(0, rtpHeaderLength).CopyTo(syntheticRtpPacket);

                            // set X bit to 0
                            syntheticRtpPacket[0] &= 0xEF;

                            // copy the original payload
                            payload.Slice(offset).CopyTo(syntheticRtpPacket.Slice(rtpHeaderLength));

                            // apply inner cryptographic algorithm
                            var innerK_e = context.K_e.Slice(0, halfContextKELength);
                            var innerK_s = context.K_s.Span.Slice(0, halfContextKSLength);
                            byte[] innerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                            SRTP.Encryption.AEAD.GenerateMessageKeyIV(innerIv, innerK_s, ssrc, index);
                            var innerAssociatedData = syntheticRtpPacket.Slice(0, rtpHeaderLength).ToArray();
                            var innerPayloadSpan = syntheticRtpPacket.Slice(rtpHeaderLength, payload.Length - rtpExtensionsLength - rtpHeaderLength);
                            var innerOutputSpan = output.Slice(offset, syntheticRtpPacketLength - rtpHeaderLength);
                            SRTP.Encryption.AEAD.Encrypt(innerOutputSpan, context.PayloadAEAD, true, innerPayloadSpan, innerIv, innerK_e, halfContextNTag, innerAssociatedData);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(rentedBuffer);
                        }

                        outputBufferLength += halfContextNTag;

                        // append OHB
                        output[outputBufferLength] = 0; // all empty OHB

                        outputBufferLength += 1;

                        // apply outer cryptographic algorithm
                        var outerK_e = context.K_e.Slice(halfContextKELength);
                        var outerK_s = context.K_s.Span.Slice(halfContextKSLength);
                        byte[] outerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(outerIv, outerK_s, ssrc, index);
                        var outerAssociatedData = output.Slice(0, offset).ToArray();

                        var outerInputSpan = output.Slice(offset, outputBufferLength - offset);
                        var outerOutputSpan = output.Slice(offset, outputBufferLength + halfContextNTag - offset);
                        SRTP.Encryption.AEAD.Encrypt(outerOutputSpan, context.PayloadAEAD, true, outerInputSpan, outerIv, outerK_e, halfContextNTag, outerAssociatedData);
                        outputBufferLength += halfContextNTag;
                    }
                    break;

                default:
                    throw new CryptographicException(ERROR_UNSUPPORTED_CIPHER);
            }


            if (context.Auth != SrtpAuth.NONE)
            {
                BinaryPrimitives.WriteUInt32BigEndian(output.Slice(payload.Length, 4), roc);
#if NET8_0_OR_GREATER
                Span<byte> auth = stackalloc byte[context.HMAC.GetMacSize()];
#else
                byte[] auth = new byte[context.HMAC.GetMacSize()];
#endif
                SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, output.Slice(0, payload.Length + 4), auth);
                auth.Slice(0, context.N_tag).CopyTo(output.Slice(payload.Length, context.N_tag));
                outputBufferLength += context.N_tag;
            }

            var mki = context.Mki;
            if (mki.Length > 0)
            {
                mki.Span.CopyTo(output.Slice(payload.Length, mki.Length));
                outputBufferLength += mki.Length;
            }

            // TODO: review
            if (sequenceNumber == 0xFFFF)
            {
                context.Roc++;
            }

            return outputBufferLength;
        }

        [SkipLocalsInit]
        public void ProtectUnprotectRtpHeaderExtensions(Span<byte> output, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> rtpExtensions, ReadOnlySpan<byte> rtpExtensionsMask, uint ssrc, uint roc, ulong index)
        {
            var context = this;

            // in case of Double AEAD, this should use the outer cryptographic key
            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    return;

                case SrtpCiphers.AES_128_F8:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.F8.GenerateRtpMessageKeyIV(iv, context.HeaderF8, context.K_he.Span, context.K_hs.Span, payload, roc);
                        SRTP.Encryption.F8.Encrypt(output, context.HeaderCTR, rtpExtensions, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.SEED_128_CTR:
                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.CTR.GenerateMessageKeyIV(iv, context.K_hs.Span, ssrc, index);
                        SRTP.Encryption.CTR.Encrypt(output, context.HeaderCTR, rtpExtensions, iv);
                    }
                    break;

                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        var outerK_hs = context.K_hs.Span.Slice(context.K_hs.Length / 2).AsBytes();
#if NET8_0_OR_GREATER
                        Span<byte> outerIv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var outerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.CTR.GenerateMessageKeyIV(outerIv, outerK_hs, ssrc, index);
                        SRTP.Encryption.CTR.Encrypt(output, context.HeaderCTR, rtpExtensions, outerIv);
                    }
                    break;

                default:
                    throw new CryptographicException(ERROR_UNSUPPORTED_CIPHER);
            }

            for (var i = 0; i < output.Length; i++)
            {
                // EncryptedHeader = (Encrypt(Key, Plaintext) AND MASK) OR (Plaintext AND (NOT MASK))
                output[i] = unchecked((byte)((output[i] & rtpExtensionsMask[i]) | (rtpExtensions[i] & ~rtpExtensionsMask[i])));
            }
            return;
        }

        public int UnprotectRtp(Span<byte> output, ReadOnlySpan<byte> payload)
        {
            var context = this;

            Throw.IfEmpty(payload);

            var mki = context.Mki;

            for (var i = 0; i < mki.Length; i++)
            {
                if (payload[payload.Length - mki.Length - context.N_tag + i] != mki.Span[i])
                {
                    Throw.CryptographicException(ERROR_MKI_CHECK_FAILED);
                }
            }

            if (!context.IncrementMasterKeyUseCounter())
            {
                Throw.CryptographicException(ERROR_MASTER_KEY_ROTATION_REQUIRED);
            }

            uint ssrc = RtpReader.ReadSsrc(payload);
            ushort sequenceNumber = RtpReader.ReadSequenceNumber(payload);

            if (context.Auth != SrtpAuth.NONE)
            {
                // TODO: optimize memory allocation - we could preallocate 4 byte array and add another GenerateAuthTag overload that processes 2 blocks
                int authenticatedLen = payload.Length - mki.Length - context.N_tag;
                var msgAuth = GC.AllocateUninitializedArray<byte>(authenticatedLen + 4);
                payload.Slice(0, authenticatedLen).CopyTo(msgAuth);
                BinaryPrimitives.WriteUInt32BigEndian(msgAuth.AsSpan(authenticatedLen, 4), context.Roc);

#if NET8_0_OR_GREATER
                Span<byte> auth = stackalloc byte[context.HMAC.GetMacSize()];
#else
                byte[] auth = new byte[context.HMAC.GetMacSize()];
#endif
                SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, msgAuth.AsSpan(0, authenticatedLen + 4), auth);
                for (var i = 0; i < context.N_tag; i++)
                {
                    if (payload[authenticatedLen + mki.Length + i] != auth[i])
                    {
                        Throw.CryptographicException(ERROR_HMAC_CHECK_FAILED);
                    }
                }

                msgAuth = null;
            }

            SsrcSrtpContext ssrcContext;
            if (context.ReplayProtection.TryGetValue(ssrc, out ssrcContext) == false)
            {
                ssrcContext = new SsrcSrtpContext();
                context.ReplayProtection.Add(ssrc, ssrcContext);
            }

            ssrcContext.SetInitialSequence(sequenceNumber);

            int offset = RtpReader.ReadHeaderLen(payload);
            uint roc = context.Roc;
            uint index = SrtpContext.DetermineRtpIndex(ssrcContext.S_l, sequenceNumber, roc);

            if (!ssrcContext.CheckAndUpdateReplayWindow(index))
            {
                Throw.CryptographicException(ERROR_REPLAY_CHECK_FAILED);
            }

            int outputBufferLength = payload.Length;
            payload.Slice(0, offset).CopyTo(output);

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    {
                        payload.Slice(0, output.Length).CopyTo(output);
                        outputBufferLength = payload.Length - mki.Length - context.N_tag;
                    }
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.F8.GenerateRtpMessageKeyIV(iv, context.PayloadF8, context.K_e.Span, context.K_s.Span, payload, roc);
                        var payloadSpan = output.Slice(offset, payload.Length - mki.Length - context.N_tag - offset);
                        SRTP.Encryption.F8.Encrypt(payloadSpan, context.PayloadCTR, payload.Slice(offset, payload.Length - mki.Length - context.N_tag - offset), iv);
                        outputBufferLength = payload.Length - mki.Length - context.N_tag;
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.SEED_128_CTR:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.CTR.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.CTR.BLOCK_SIZE);
#endif
                        SRTP.Encryption.CTR.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, index);
                        var payloadSpan = output.Slice(offset, payload.Length - mki.Length - context.N_tag - offset);
                        SRTP.Encryption.CTR.Encrypt(payloadSpan, context.PayloadCTR, payload.Slice(offset, payload.Length - mki.Length - context.N_tag - offset), iv);
                        outputBufferLength = payload.Length - mki.Length - context.N_tag;
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, index);
                        var associatedData = payload.Slice(0, offset).ToArray();
                        var inputSpan = payload.Slice(offset);
                        var outputSpan = output.Slice(offset, payload.Length - offset + context.N_tag);
                        SRTP.Encryption.AEAD.Encrypt(outputSpan, context.PayloadAEAD, false, inputSpan, iv, context.K_e.ToArray(), context.N_tag, associatedData);
                        outputBufferLength = payload.Length - 4 - context.N_tag - mki.Length;
                    }
                    break;

                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        var halfContextNTag = context.N_tag / 2;
                        var halfContextKELength = context.K_e.Length / 2;
                        var halfContextKSLength = context.K_s.Length / 2;

                        // apply outer cryptographic algorithm - decrypt/verify
                        var outerK_e = context.K_e.Slice(halfContextKELength);
                        var outerK_s = context.K_s.Slice(halfContextKSLength);
                        var outerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(outerIv, outerK_s.Span, ssrc, index);
                        var outerAssociatedData = payload.Slice(0, offset).ToArray();

                        var outerInputSpan = payload.Slice(offset, payload.Length - offset - mki.Length);
                        var outerOutputSpan = output.Slice(offset);
                        SRTP.Encryption.AEAD.Encrypt(outerOutputSpan, context.PayloadAEAD, false, outerInputSpan, outerIv, outerK_e, halfContextNTag, outerAssociatedData);

                        // calculate OHB size - it can now be larger than 1 byte if it was modified
                        var lastOhbByteIndex = payload.Length - mki.Length - halfContextNTag - 1;
                        var ohbConfig = output[lastOhbByteIndex];
                        var ohbLength = 1;
                        if ((ohbConfig & 0x01) == 0x01)
                        {
                            ohbLength += 2;
                        }
                        if ((ohbConfig & 0x02) == 0x02)
                        {
                            ohbLength += 1;
                        }

                        // form a synthetic RTP packet
                        var rtpHeaderLength = RtpReader.ReadHeaderLenWithoutExtensions(payload);
                        var rtpExtensionsLength = RtpReader.ReadExtensionsLength(payload);

                        int syntheticRtpPacketLength = payload.Length - rtpExtensionsLength - halfContextNTag - ohbLength;
                        var rentedBuffer = ArrayPool<byte>.Shared.Rent(syntheticRtpPacketLength);

                        try
                        {
                            var syntheticRtpPacket = rentedBuffer.AsSpan(0, syntheticRtpPacketLength);

                            // copy header without extensions
                            payload.Slice(0, rtpHeaderLength).CopyTo(syntheticRtpPacket);

                            // set X bit to 0
                            syntheticRtpPacket[0] &= 0xEF;

                            // restore original header values from the OHB
                            if ((ohbConfig & 0x01) == 0x01)
                            {
                                syntheticRtpPacket[2] = payload[lastOhbByteIndex - ohbLength - 1];
                                syntheticRtpPacket[3] = payload[lastOhbByteIndex - ohbLength];
                            }
                            if ((ohbConfig & 0x02) == 0x02)
                            {
                                var pt = payload[lastOhbByteIndex - ohbLength];
                                syntheticRtpPacket[1] = (byte)((syntheticRtpPacket[1] & 0x80) | (pt & 0x7F));
                            }
                            if ((ohbConfig & 0x04) == 0x04)
                            {
                                var markerBit = (ohbConfig & 0x08) == 0x08;
                                syntheticRtpPacket[1] = (byte)((markerBit ? 0x80 : 0x00) | (syntheticRtpPacket[1] & 0x7F));
                            }

                            // copy the payload including the inner authentication tag
                            output.Slice(offset, payload.Length - offset - mki.Length - halfContextNTag - ohbLength).CopyTo(syntheticRtpPacket.Slice(rtpHeaderLength));

                            uint innerSsrc = RtpReader.ReadSsrc(syntheticRtpPacket);
                            ushort innerSequenceNumber = RtpReader.ReadSequenceNumber(syntheticRtpPacket);
                            uint innerIndex = SrtpContext.DetermineRtpIndex(ssrcContext.S_l, sequenceNumber, roc);

                            // apply inner cryptographic algorithm
                            var innerK_e2 = context.K_e.Slice(0, halfContextKELength);
                            var innerK_s2 = context.K_s.Span.Slice(0, halfContextKSLength);
                            var innerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                            SRTP.Encryption.AEAD.GenerateMessageKeyIV(innerIv, innerK_s2, ssrc, index);
                            var innerAssociatedData2 = syntheticRtpPacket.Slice(0, rtpHeaderLength).ToArray();

                            var innerInputSpan = syntheticRtpPacket.Slice(rtpHeaderLength);
                            var innerOutputSpan = syntheticRtpPacket.Slice(rtpHeaderLength);
                            SRTP.Encryption.AEAD.Encrypt(innerOutputSpan, context.PayloadAEAD, false, innerInputSpan, innerIv, innerK_e2, halfContextNTag, innerAssociatedData2);

                            // copy the unprotected payload back to the output buffer
                            syntheticRtpPacket.Slice(rtpHeaderLength, syntheticRtpPacketLength - rtpHeaderLength - halfContextNTag).CopyTo(output.Slice(offset, syntheticRtpPacketLength - rtpHeaderLength - halfContextNTag));

                            outputBufferLength = offset + syntheticRtpPacketLength - rtpHeaderLength - halfContextNTag;
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(rentedBuffer);
                        }
                    }
                    break;

                default:
                    throw new CryptographicException(ERROR_UNSUPPORTED_CIPHER);
            }

            // because of CCM/GCM, RTP headers must be unprotected only after the payload is unprotected and HMAC is verified
            // RFC6904
            var rtpExtensionsMask = RtpHeaderExtensionsEncryptionMask;
            if (!rtpExtensionsMask.IsEmpty)
            {
                int rtpExtensionsOffset = RtpReader.ReadHeaderLenWithoutExtensions(payload) + 4;
                if (RtpReader.ReadExtensionsLength(payload) <= 0)
                {
                    Throw.InvalidOperationException("RTP header extensions encryption mask is set, but the RTP packet does not contain any header extensions!");
                }

                var rtpExtensions = RtpReader.ReadHeaderExtensions(payload);
                Span<byte> rtpExtensionsOutput = stackalloc byte[rtpExtensions.Length];
                ProtectUnprotectRtpHeaderExtensions(rtpExtensionsOutput, payload, rtpExtensions.ToArray(), rtpExtensionsMask.Span, ssrc, roc, index);
                rtpExtensionsOutput.CopyTo(output.Slice(rtpExtensionsOffset, rtpExtensions.Length));
            }

            return outputBufferLength;
        }

        public virtual int CalculateRequiredSrtcpPayloadLength(int rtcpLen)
        {
            var context = this;
            var mki = context.Mki;
            return rtcpLen + 4 + mki.Length + context.N_tag;
        }

        [SkipLocalsInit]
        public int ProtectRtcp(Span<byte> output, ReadOnlySpan<byte> payload)
        {
            var context = this;

            Throw.IfEmpty(payload);

            Throw.IfLessThan(output.Length, CalculateRequiredSrtcpPayloadLength(payload.Length));

            if (!context.IncrementMasterKeyUseCounter())
            {
                Throw.CryptographicException(ERROR_MASTER_KEY_ROTATION_REQUIRED);
            }

            uint ssrc = RtcpReader.ReadSsrc(payload);
            int offset = RtcpReader.GetHeaderLen();

            SsrcSrtpContext ssrcContext;
            if (context.ReplayProtection.TryGetValue(ssrc, out ssrcContext) == false)
            {
                ssrcContext = new SsrcSrtpContext();
                context.ReplayProtection.Add(ssrc, ssrcContext);
            }

            uint index = ssrcContext.S_l | E_FLAG;

            var outputBufferLength = payload.Length;

            switch (context.Cipher)
            {
                case SrtpCiphers.NULL:
                    break;

                case SrtpCiphers.AES_128_F8:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                        SRTP.Encryption.F8.GenerateRtcpMessageKeyIV(iv, context.PayloadF8, context.K_e.Span, context.K_s.Span, payload, index);
                        var payloadSpan = payload.Slice(offset);
                        SRTP.Encryption.F8.Encrypt(output, context.PayloadCTR, payloadSpan, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_192_CM:
                case SrtpCiphers.AES_256_CM:
                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                case SrtpCiphers.SEED_128_CTR:
                    {
#if NET8_0_OR_GREATER
                        Span<byte> iv = stackalloc byte[SRTP.Encryption.CTR.BLOCK_SIZE];
#else
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.CTR.BLOCK_SIZE);
#endif
                        SRTP.Encryption.CTR.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, ssrcContext.S_l);
                        var payloadSpan = payload.Slice(offset);
                        SRTP.Encryption.CTR.Encrypt(output, context.PayloadCTR, payloadSpan, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                case SrtpCiphers.SEED_128_CCM:
                case SrtpCiphers.SEED_128_GCM:
                    {
                        var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, ssrcContext.S_l);
                        var associatedData = GC.AllocateUninitializedArray<byte>(offset + 4);
                        payload.Slice(0, offset).CopyTo(associatedData);
                        BinaryPrimitives.WriteUInt32BigEndian(associatedData.AsSpan(offset, 4), (uint)index);
                        var payloadSpan = payload.Slice(offset, payload.Length - offset + context.N_tag);
                        var outputSpan = output.Slice(offset, payload.Length - offset + context.N_tag);
                        SRTP.Encryption.AEAD.Encrypt(outputSpan, context.PayloadAEAD, true, payload.Slice(offset), iv, context.K_e, context.N_tag, associatedData);
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                    {
                        // RTCP under Double AEAD is protected only with the outer layer
                        var outerK_e2 = context.K_e.Slice(context.K_e.Length / 2);
                        var outerK_s2 = context.K_s.Span.Slice(context.K_s.Length / 2);
                        var outerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                        SRTP.Encryption.AEAD.GenerateMessageKeyIV(outerIv, outerK_s2, ssrc, ssrcContext.S_l);
                        var associatedData2 = GC.AllocateUninitializedArray<byte>(offset + 4);
                        payload.Slice(0, offset).CopyTo(associatedData2);
                        payload.Slice(payload.Length - 4, 4).CopyTo(associatedData2.AsSpan(offset, 4));
                        var payloadSpan = payload.Slice(offset, payload.Length - offset + context.N_tag / 2);
                        SRTP.Encryption.AEAD.Encrypt(output, context.PayloadAEAD, true, payload.Slice(offset), outerIv, outerK_e2, context.N_tag / 2, associatedData2);
                        outputBufferLength += context.N_tag / 2;
                    }
                    break;

                default:
                    throw new CryptographicException(ERROR_UNSUPPORTED_CIPHER);
            }

            BinaryPrimitives.WriteUInt32BigEndian(output.Slice(payload.Length, 4), index);
            outputBufferLength += 4;

            var mki = context.Mki;
            if (mki.Length > 0)
            {
                mki.Span.CopyTo(output.Slice(payload.Length, mki.Length));
                outputBufferLength += mki.Length;
            }

            if (context.Auth != SrtpAuth.NONE)
            {
#if NET8_0_OR_GREATER
                Span<byte> auth = stackalloc byte[context.HMAC.GetMacSize()];
#else
                byte[] auth = new byte[context.HMAC.GetMacSize()];
#endif
                SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, payload, auth);
                auth.AsSpan(0, context.N_tag).CopyTo(output.Slice(payload.Length, context.N_tag));
                outputBufferLength += context.N_tag;
            }

            ssrcContext.SetSequence((ushort)((ssrcContext.S_l + 1) % 0x80000000));

            return payload.Length;
        }

        [SkipLocalsInit]
        public int UnprotectRtcp(Span<byte> output, ReadOnlySpan<byte> payload)
        {
            var context = this;

            Throw.IfEmpty(payload);

            var mki = context.Mki;

            for (var i = 0; i < mki.Length; i++)
            {
                if (payload[payload.Length - context.N_tag - mki.Length + i] != mki.Span[i])
                {
                    Throw.CryptographicException(ERROR_MKI_CHECK_FAILED);
                }
            }

            if (!context.IncrementMasterKeyUseCounter())
            {
                Throw.CryptographicException(ERROR_MASTER_KEY_ROTATION_REQUIRED);
            }

            uint ssrc = RtcpReader.ReadSsrc(payload);
            int offset = RtcpReader.GetHeaderLen();

            SsrcSrtpContext ssrcContext;
            if (context.ReplayProtection.TryGetValue(ssrc, out ssrcContext) == false)
            {
                ssrcContext = new SsrcSrtpContext();
                context.ReplayProtection.Add(ssrc, ssrcContext);
            }

            uint index = RtcpReader.SrtcpReadIndex(payload, context.N_a > 0 ? (context.N_tag + mki.Length) : 0);
            bool isEncrypted = false;

            if ((index & E_FLAG) == E_FLAG)
            {
                index = index & ~E_FLAG;
                isEncrypted = true;
            }

            if (context.Auth != SrtpAuth.NONE)
            {
#if NET8_0_OR_GREATER
                Span<byte> auth = stackalloc byte[context.HMAC.GetMacSize()];
#else
                byte[] auth = new byte[context.HMAC.GetMacSize()];
#endif
                SRTP.Authentication.HMAC.GenerateAuthTag(context.HMAC, payload.Slice(0, payload.Length - context.N_tag - mki.Length), auth);
                for (var i = 0; i < context.N_tag; i++)
                {
                    if (payload[payload.Length - context.N_tag + i] != auth[i])
                    {
                        Throw.CryptographicException(ERROR_HMAC_CHECK_FAILED);
                    }
                }
            }

            if (!ssrcContext.CheckAndUpdateReplayWindow(index))
            {
                Throw.CryptographicException(ERROR_REPLAY_CHECK_FAILED);
            }

            int outputBufferLength;

            if (isEncrypted)
            {
                switch (context.Cipher)
                {
                    case SrtpCiphers.NULL:
                        {
                            outputBufferLength = payload.Length - 4 - context.N_tag - mki.Length;
                        }
                        break;

                    case SrtpCiphers.AES_128_F8:
                        {
#if NET8_0_OR_GREATER
                            Span<byte> iv = stackalloc byte[SRTP.Encryption.F8.BLOCK_SIZE];
#else
                            var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.F8.BLOCK_SIZE);
#endif
                            SRTP.Encryption.F8.GenerateRtcpMessageKeyIV(iv, context.PayloadF8, context.K_e.Span, context.K_s.Span, payload, index);
                            var payloadSpan = payload.Slice(offset, payload.Length - 4 - context.N_tag - mki.Length - offset);
                            var outputSpan = output.Slice(offset, payload.Length - 4 - context.N_tag - mki.Length - offset);
                            SRTP.Encryption.F8.Encrypt(outputSpan, context.PayloadCTR, payloadSpan, iv);
                            outputBufferLength = payload.Length - 4 - context.N_tag - mki.Length;
                        }
                        break;

                    case SrtpCiphers.AES_128_CM:
                    case SrtpCiphers.AES_192_CM:
                    case SrtpCiphers.AES_256_CM:
                    case SrtpCiphers.ARIA_128_CTR:
                    case SrtpCiphers.ARIA_256_CTR:
                    case SrtpCiphers.SEED_128_CTR:
                        {
#if NET8_0_OR_GREATER
                            Span<byte> iv = stackalloc byte[SRTP.Encryption.CTR.BLOCK_SIZE];
#else
                            var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.CTR.BLOCK_SIZE);
#endif
                            SRTP.Encryption.CTR.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, ssrcContext.S_l);
                            var payloadSpan = payload.Slice(offset, payload.Length - 4 - context.N_tag - mki.Length - offset);
                            var outputSpan = output.Slice(offset, payload.Length - 4 - context.N_tag - mki.Length - offset);
                            SRTP.Encryption.CTR.Encrypt(outputSpan, context.PayloadCTR, payloadSpan, iv);
                            outputBufferLength = payload.Length - 4 - context.N_tag - mki.Length;
                        }
                        break;

                    case SrtpCiphers.AEAD_AES_128_GCM:
                    case SrtpCiphers.AEAD_AES_256_GCM:
                    case SrtpCiphers.AEAD_ARIA_128_GCM:
                    case SrtpCiphers.AEAD_ARIA_256_GCM:
                    case SrtpCiphers.SEED_128_CCM:
                    case SrtpCiphers.SEED_128_GCM:
                        {
                            var iv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                            SRTP.Encryption.AEAD.GenerateMessageKeyIV(iv, context.K_s.Span, ssrc, ssrcContext.S_l);
                            var associatedData = GC.AllocateUninitializedArray<byte>(offset + 4);
                            payload.Slice(0, offset).CopyTo(associatedData);
                            // Copy 4-byte index from payload into associatedData, preserving big-endian
                            payload.Slice(payload.Length - 4, 4).CopyTo(associatedData.AsSpan(offset, 4));
                            var inputSpan = payload.Slice(offset, payload.Length - 4 - mki.Length - context.N_tag - offset);
                            var outputSpan = output.Slice(offset, payload.Length - 4 - mki.Length - offset);
                            SRTP.Encryption.AEAD.Encrypt(outputSpan, context.PayloadAEAD, false, inputSpan, iv, context.K_e, context.N_tag, associatedData);
                            outputBufferLength = payload.Length - 4 - context.N_tag - mki.Length;
                        }
                        break;

                    case SrtpCiphers.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM:
                    case SrtpCiphers.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM:
                        {
                            // RTCP under Double AEAD is protected only with the outer layer - decrypt
                            var outerK_e3 = context.K_e.Slice(context.K_e.Length / 2);
                            var outerK_s3 = context.K_s.Span.Slice(context.K_s.Length / 2);
                            var outerIv = GC.AllocateUninitializedArray<byte>(SRTP.Encryption.AEAD.BLOCK_SIZE);
                            SRTP.Encryption.AEAD.GenerateMessageKeyIV(outerIv, outerK_s3, ssrc, ssrcContext.S_l);
                            var associatedData3 = GC.AllocateUninitializedArray<byte>(offset + 4);
                            payload.Slice(0, offset).CopyTo(associatedData3);
                            payload.Slice(payload.Length - 4, 4).CopyTo(associatedData3.AsSpan(offset, 4));
                            var rtcpInputSpan = payload.Slice(offset, payload.Length - 4 - mki.Length - context.N_tag / 2 - offset);
                            var rtcpOutputSpan = output.Slice(offset, payload.Length - 4 - mki.Length - offset);
                            SRTP.Encryption.AEAD.Encrypt(rtcpOutputSpan, context.PayloadAEAD, false, rtcpInputSpan, outerIv, outerK_e3, context.N_tag / 2, associatedData3);
                            outputBufferLength = payload.Length - 4 - context.N_tag / 2 - mki.Length;
                        }
                        break;

                    default:
                        throw new CryptographicException(ERROR_UNSUPPORTED_CIPHER);
                }
            }
            else
            {
                outputBufferLength = payload.Length;
            }

            return outputBufferLength;
        }

        public static uint DetermineRtpIndex(uint s_l, ushort SEQ, ulong ROC)
        {
            // RFC 3711 - Appendix A
            ulong v;
            if (s_l < 32768)
            {
                if (SEQ - s_l > 32768)
                {
                    v = (ROC - 1) % 4294967296L;
                }
                else
                {
                    v = ROC;
                }
            }
            else
            {
                if (s_l - 32768 > SEQ)
                {
                    v = (ROC + 1) % 4294967296L;
                }
                else
                {
                    v = ROC;
                }
            }
            return (uint)(SEQ + v * 65536U);
        }

        public static ulong GenerateRtpIndex(uint ROC, ushort SEQ)
        {
            // RFC 3711 - 3.3.1
            // i = 2 ^ 16 * ROC + SEQ
            return ((ulong)ROC << 16) | SEQ;
        }

        /// <summary>
        /// Increments the master key use counter.
        /// </summary>
        public virtual bool IncrementMasterKeyUseCounter()
        {
            var currentValue = Interlocked.Increment(ref _masterKeySentCounter);
            var maxAllowedValue = _contextType == SrtpContextType.RTP ? 281474976710656L : 2147483648L;
            if (currentValue >= maxAllowedValue)
            {
                OnRekeyingRequested?.Invoke(this, EventArgs.Empty);

                // at this point we shall not transmit any other packets protected by these keys
                return false;
            }

            return true;
        }
    }
}
