using BenchmarkDotNet.Attributes;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;

namespace SharpSRTP.Benchmarks
{
    public class SrtpSessionContextDtlsSrtpProtocolBenchmarks
    {
        private const string DtlsSrtpMasterKeySaltBase64 = "f7d54b1f77018d00a48438d4be6d1b59be683885ec77dde0d18a1e1e566044aa00fb3c11179f6a224763350e26634b952e00d0e34f6ef57b41aecbc8216832bbf18389d0f58f861065f337b8ffdb115c585cfef1019b19d71579a1792d0a6ac7467efa2e39ec36a4a75c1ff9c1f599e2";

        private DtlsSrtpKeys _dtlsSrtpKeys;

        [GlobalSetup]
        public void GlobalSetup()
        {
            _dtlsSrtpKeys = DtlsSrtpProtocol.CreateMasterKeys(ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM, null, Convert.FromBase64String(DtlsSrtpMasterKeySaltBase64));
        }

        [Benchmark]
        public SrtpSessionContext CreateSrtpClientSessionContext()
        {
            return DtlsSrtpProtocol.CreateSrtpClientSessionContext(_dtlsSrtpKeys);
        }
    }
}
