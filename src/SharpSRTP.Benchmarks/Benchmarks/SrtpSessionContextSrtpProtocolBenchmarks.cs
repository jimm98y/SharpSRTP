using BenchmarkDotNet.Attributes;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;

namespace SharpSRTP.Benchmarks
{
    public class SrtpSessionContextSrtpProtocolBenchmarks
    {
        private const string SrtpMasterKeySaltBase64 = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";

        private SrtpKeys _srtpKeys;

        [GlobalSetup]
        public void GlobalSetup()
        {
            _srtpKeys = SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, Convert.FromBase64String(SrtpMasterKeySaltBase64));
        }

        [Benchmark]
        public SrtpSessionContext CreateSrtpSessionContext()
        {
            return SrtpProtocol.CreateSrtpSessionContext(_srtpKeys);
        }
    }
}
