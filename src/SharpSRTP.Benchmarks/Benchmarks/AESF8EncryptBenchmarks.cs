using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SharpSRTP.SRTP.Encryption;
using SharpSRTP.SRTP.Readers;
using System;

namespace SharpSRTP.Benchmarks
{
    public class AESF8EncryptBenchmarks
    {
        private static readonly byte[] k_e;
        private static readonly byte[] k_s;
        private static readonly byte[] rtpBytesSource;
        private static readonly uint roc = 0xd462564a;
        private byte[] rtpBytes;
        private IBlockCipher aes;

        static AESF8EncryptBenchmarks()
        {
            k_e = Convert.FromHexString("234829008467be186c3de14aae72d62c");
            k_s = Convert.FromHexString("32f2870d");
            rtpBytesSource = Convert.FromHexString("806e5cba50681de55c62159970736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67");
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
        }

        [IterationSetup]
        public void IterationSetup()
        {
            aes = AesUtilities.CreateEngine();
            rtpBytes = new byte[rtpBytesSource.Length];
            Buffer.BlockCopy(rtpBytesSource, 0, rtpBytes, 0, rtpBytesSource.Length);

            uint sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytesSource);
            uint ssrc = RtpReader.ReadSsrc(rtpBytesSource);
            int offset = RtpReader.ReadHeaderLen(rtpBytesSource);
            ulong index = ((ulong)roc << 16) | sequenceNumber;
        }

        [Benchmark]
        public void AESF8_Encrypt()
        {
            int offset = RtpReader.ReadHeaderLen(rtpBytesSource);

#if LibVersion && !LibVersion_0_4_0
            var iv = F8.GenerateRtpMessageKeyIV(aes, k_e, k_s, rtpBytesSource, roc);
#else
#if NET8_0_OR_GREATER
            Span<byte> iv = stackalloc byte[F8.BLOCK_SIZE];
#else
            var iv = new byte[F8.BLOCK_SIZE];
#endif
            F8.GenerateRtpMessageKeyIV(aes, k_e, k_s, rtpBytesSource, roc, iv);
#endif

            aes.Init(true, new KeyParameter(k_e));
#if LibVersion || LibVersion_0_4_0
            F8.Encrypt(aes, rtpBytesSource, offset, rtpBytesSource.Length, iv);
#else
            F8.Encrypt(aes, rtpBytesSource.AsSpan(offset, rtpBytesSource.Length - offset), rtpBytesSource.AsSpan(offset, rtpBytesSource.Length - offset), iv);
#endif
        }
    }
}
