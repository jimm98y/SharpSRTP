using SharpSRTP.SRTP.Authentication;
using SharpSRTP.SRTP.Encryption;
using System;
using System.Linq;

namespace SharpSRTP.SRTP
{
    public static class SRTPContextExtensions
    {
        public const uint E_FLAG = 0x80000000;

        public const int ERROR_GENERIC = -1;
        public const int ERROR_UNSUPPORTED_CIPHER = -2;
        public const int ERROR_HMAC_CHECK_FAILED = -3;
        public const int ERROR_REPLAY_CHECK_FAILED = -4;
        public const int ERROR_MASTER_KEY_ROTATION_REQUIRED = -5;

        public static int ProtectRTP(this SRTPContext ServerRtpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = ServerRtpContext;
            outputBufferLength = length;

            if(!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RTPReader.ReadSsrc(payload);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(payload);
            int offset = RTPReader.ReadHeaderLen(payload);

            uint roc = context.Roc;
            ulong index = SRTProtocol.GenerateRTPIndex(roc, sequenceNumber);

            switch (context.Cipher)
            {
                case SRTPCiphers.NULL:
                    break;

                case SRTPCiphers.AES_128_F8:
                    {
                        byte[] iv = AESF8.GenerateRTPMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AES_128_CM:
                case SRTPCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_AES_128_GCM:
                case SRTPCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SRTPCiphers.ARIA_128_CTR:
                case SRTPCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_ARIA_128_GCM:
                case SRTPCiphers.AEAD_ARIA_256_GCM:
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

            if (context.Auth != SRTPAuth.NONE)
            {
                payload[length + 0] = (byte)(roc >> 24);
                payload[length + 1] = (byte)(roc >> 16);
                payload[length + 2] = (byte)(roc >> 8);
                payload[length + 3] = (byte)roc;

                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length + 4);
                System.Buffer.BlockCopy(auth, 0, payload, length, context.N_tag); // we don't append ROC in SRTP
                outputBufferLength += context.N_tag;
            }

            if (sequenceNumber == 0xFFFF)
            {
                context.Roc++;
            }

            return 0;
        }

        public static int UnprotectRTP(this SRTPContext ClientRtpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = ClientRtpContext;
            outputBufferLength = length - context.N_tag;

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RTPReader.ReadSsrc(payload);
            ushort sequenceNumber = RTPReader.ReadSequenceNumber(payload);

            if (context.Auth != SRTPAuth.NONE)
            {
                // TODO: optimize memory allocation - we could preallocate 4 byte array and add another GenerateAuthTag overload that processes 2 blocks
                byte[] msgAuth = new byte[length + 4];
                Buffer.BlockCopy(payload, 0, msgAuth, 0, length);
                msgAuth[length + 0] = (byte)(context.Roc >> 24);
                msgAuth[length + 1] = (byte)(context.Roc >> 16);
                msgAuth[length + 2] = (byte)(context.Roc >> 8);
                msgAuth[length + 3] = (byte)(context.Roc);

                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, msgAuth, 0, length - context.N_tag + 4);
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

            int offset = RTPReader.ReadHeaderLen(payload);
            uint roc = context.Roc;
            uint index = SRTProtocol.DetermineRTPIndex(context.S_l, sequenceNumber, roc);

            if (!context.CheckAndUpdateReplayWindow(index))
            {
                return ERROR_REPLAY_CHECK_FAILED;
            }

            switch (context.Cipher)
            {
                case SRTPCiphers.NULL:
                    break;

                case SRTPCiphers.AES_128_F8:
                    {
                        byte[] iv = AESF8.GenerateRTPMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, roc);
                        AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SRTPCiphers.AES_128_CM:
                case SRTPCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_AES_128_GCM:
                case SRTPCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        byte[] associatedData = payload.Take(offset).ToArray();
                        AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                    }
                    break;

                case SRTPCiphers.ARIA_128_CTR:
                case SRTPCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, index);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_ARIA_128_GCM:
                case SRTPCiphers.AEAD_ARIA_256_GCM:
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

        public static int ProtectRTCP(this SRTPContext serverRtcpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = serverRtcpContext;
            outputBufferLength = length;

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RTCPReader.ReadSsrc(payload);
            int offset = RTCPReader.GetHeaderLen();
            uint index = context.S_l | E_FLAG;

            switch (context.Cipher)
            {
                case SRTPCiphers.NULL:
                    break;

                case SRTPCiphers.AES_128_F8:
                    {
                        byte[] iv = AESF8.GenerateRTCPMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                        AESF8.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AES_128_CM:
                case SRTPCiphers.AES_256_CM:
                    {
                        byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        AESCM.Encrypt(context.AES, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_AES_128_GCM:
                case SRTPCiphers.AEAD_AES_256_GCM:
                    {
                        byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        byte[] associatedData = payload.Take(offset).Concat(new byte[] { (byte)(index >> 24), (byte)(index >> 16), (byte)(index >> 8), (byte)index }).ToArray(); // associatedData include also index
                        AESGCM.Encrypt(context.AESGCM, payload, offset, length, iv, context.K_e, context.N_tag, associatedData);
                        length += context.N_tag;
                        outputBufferLength += context.N_tag;
                    }
                    break;

                case SRTPCiphers.ARIA_128_CTR:
                case SRTPCiphers.ARIA_256_CTR:
                    {
                        byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                        ARIACTR.Encrypt(context.ARIA, payload, offset, length, iv);
                    }
                    break;

                case SRTPCiphers.AEAD_ARIA_128_GCM:
                case SRTPCiphers.AEAD_ARIA_256_GCM:
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

            if (context.Auth != SRTPAuth.NONE)
            {
                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length + 4);
                System.Buffer.BlockCopy(auth, 0, payload, length + 4, context.N_tag);
                outputBufferLength += context.N_tag;
            }

            context.S_l = (context.S_l + 1) % 0x80000000;

            return 0;
        }

        public static int UnprotectRTCP(this SRTPContext clientRtcpContext, byte[] payload, int length, out int outputBufferLength)
        {
            var context = clientRtcpContext;
            outputBufferLength = length - 4 - context.N_tag;

            if (!context.IncrementMasterKeyUseCounter())
            {
                return ERROR_MASTER_KEY_ROTATION_REQUIRED;
            }

            uint ssrc = RTCPReader.ReadSsrc(payload);
            int offset = RTCPReader.GetHeaderLen();
            uint index = RTCPReader.SRTCPReadIndex(payload, context.N_a > 0 ? context.N_tag : 0);
            bool isEncrypted = false;

            if ((index & E_FLAG) == E_FLAG)
            {
                index = index & ~E_FLAG;
                isEncrypted = true;
            }

            if (context.Auth != SRTPAuth.NONE)
            {
                byte[] auth = HMAC.GenerateAuthTag(context.HMAC, payload, 0, length - context.N_tag);
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
                    case SRTPCiphers.NULL:
                        break;

                    case SRTPCiphers.AES_128_F8:
                        {
                            byte[] iv = AESF8.GenerateRTCPMessageKeyIV(context.AESF8, context.K_e, context.K_s, payload, index);
                            AESF8.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SRTPCiphers.AES_128_CM:
                    case SRTPCiphers.AES_256_CM:
                        {
                            byte[] iv = AESCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            AESCM.Encrypt(context.AES, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SRTPCiphers.AEAD_AES_128_GCM:
                    case SRTPCiphers.AEAD_AES_256_GCM:
                        {
                            byte[] iv = AESGCM.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            byte[] associatedData = payload.Take(offset).Concat(payload.Skip(length - 4).Take(4)).ToArray(); // associatedData include also index
                            AESGCM.Encrypt(context.AESGCM, payload, offset, outputBufferLength, iv, context.K_e, context.N_tag, associatedData);
                        }
                        break;

                    case SRTPCiphers.ARIA_128_CTR:
                    case SRTPCiphers.ARIA_256_CTR:
                        {
                            byte[] iv = ARIACTR.GenerateMessageKeyIV(context.K_s, ssrc, context.S_l);
                            ARIACTR.Encrypt(context.ARIA, payload, offset, outputBufferLength, iv);
                        }
                        break;

                    case SRTPCiphers.AEAD_ARIA_128_GCM:
                    case SRTPCiphers.AEAD_ARIA_256_GCM:
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
