using BenchmarkDotNet.Attributes;
using SharpSRTP.SRTP;
using System;

namespace SharpSRTP.Benchmarks
{
    public class SrtpProtocolBenchmarks
    {
        private const string MasterKeySaltBase64 = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";

        private byte[] _masterKeySaltBytes;

        [GlobalSetup]
        public void GlobalSetup()
        {
            _masterKeySaltBytes = Convert.FromBase64String(MasterKeySaltBase64);
        }

        [Benchmark]
        public SrtpKeys CreateMasterKeys()
        {
            return SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, _masterKeySaltBytes);
        }
    }
}
