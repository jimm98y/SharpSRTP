using SharpSRTP.SRTP.Authentication;
using SharpSRTP.SRTP.Encryption;
using System;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public static class SrtpContextEncryptionExtensions
    {
        public const uint E_FLAG = 0x80000000;

        public const int ERROR_GENERIC = -1;
        public const int ERROR_UNSUPPORTED_CIPHER = -2;
        public const int ERROR_HMAC_CHECK_FAILED = -3;
        public const int ERROR_REPLAY_CHECK_FAILED = -4;
        public const int ERROR_MASTER_KEY_ROTATION_REQUIRED = -5;
        public const int ERROR_MKI_CHECK_FAILED = -6;

        public static int ProtectRTP(this SrtpContext encodeRtpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = encodeRtpContext;
            outputBufferLength = length;

            if(!context.IncrementMasterKeyUseCounter())
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
                        byte[] iv = AESF8.GenerateRtpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
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

                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length + 4);
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

        public static int UnprotectRTP(this SrtpContext decodeRtpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = decodeRtpContext;

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

                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, msgAuth, 0, authenticatedLen + 4);
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
                        byte[] iv = AESF8.GenerateRtpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                    }
                    break;

                default:
                    return ERROR_UNSUPPORTED_CIPHER;
            }

            return 0;
        }

        public static int ProtectRTCP(this SrtpContext encodeRtcpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = encodeRtcpContext;
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
                        byte[] iv = AESF8.GenerateRtcpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                        AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AES_128_CM:
                case SrtpCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_AES_128_GCM:
                case SrtpCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        byte[] associatedData = payload.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
                        AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SrtpCiphers.ARIA_128_CTR:
                case SrtpCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SrtpCiphers.AEAD_ARIA_128_GCM:
                case SrtpCiphers.AEAD_ARIA_256_GCM:
                    {
                        byte[] iv = ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        byte[] associatedData = payload.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
                        ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
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
                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length);
                System.Buffer.BlockCopy(auth, 0, payload, length, context.N_tag);
                length += context.N_tag;
                outputBufferLength += context.N_tag;
            }

            context.S_l = (context.S_l + 1) % 0x80000000;

            return 0;
        }

        public static int UnprotectRTCP(this SrtpContext decodeRtcpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = decodeRtcpContext;

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
                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length - context.N_tag - mki.Length);
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
                            byte[] iv = AESF8.GenerateRtcpMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                            AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AES_128_CM:
                    case SrtpCiphers.AES_256_CM:
                        {
                            byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AEAD_AES_128_GCM:
                    case SrtpCiphers.AEAD_AES_256_GCM:
                        {
                            byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            byte[] associatedData = payload.Take(offset).Concat(payload.Skip(length - 4).Take(4)).ToArray(); // associatedData include also index
                            AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                        }
                        break;

                    case SrtpCiphers.ARIA_128_CTR:
                    case SrtpCiphers.ARIA_256_CTR:
                        {
                            byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SrtpCiphers.AEAD_ARIA_128_GCM:
                    case SrtpCiphers.AEAD_ARIA_256_GCM:
                        {
                            byte[] iv = ARIAGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            byte[] associatedData = payload.Take(offset).Concat(payload.Skip(length - 4).Take(4)).ToArray(); // associatedData include also index
                            ARIAGCM.Encrypt(context.ARIAGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                        }
                        break;

                    default:
                        return ERROR_UNSUPPORTED_CIPHER;
                }
            }

            return 0;
        }
    }
}
