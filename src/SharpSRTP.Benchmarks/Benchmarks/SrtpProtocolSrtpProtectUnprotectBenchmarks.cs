using BenchmarkDotNet.Attributes;
using SharpSRTP.SRTP;
using System;
using System.Collections.Generic;

namespace SharpSRTP.Benchmarks
{
    public class SrtpProtocolSrtpProtectUnprotectBenchmarks
    {
        [ParamsSource(nameof(SettingsSource))]
        public RtpProtectUnprotectSettings Settings { get; set; }


        [Benchmark]
        public void Srtp_Protect_Unprotect()
        {
            Settings.Context.ProtectRtp(Settings.SrtpBytes, Settings.RtpBytes.Length, out var len);

            Settings.Context.UnprotectRtp(Settings.SrtpBytes, len, out var _);
        }

        public static IEnumerable<RtpProtectUnprotectSettings> SettingsSource =>
            new[]
            {
                new RtpProtectUnprotectSettings(
                    cryptoSuite: nameof(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80),
                    context: SrtpProtocol.CreateSrtpSessionContext(
                        SrtpProtocol.CreateMasterKeys(
                            SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80,
                            null,
                            Convert.FromBase64String("n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi"))),
                    rtpBytes: Convert.FromHexString("80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0")),
            };

        public sealed class RtpProtectUnprotectSettings
        {
            public RtpProtectUnprotectSettings(
                string cryptoSuite,
                SrtpSessionContext context,
                byte[] rtpBytes)
            {
                CryptoSuite = cryptoSuite;
                Context = context;
                RtpBytes = new byte[rtpBytes.Length];
                SrtpBytes = new byte[Context.CalculateRequiredSrtpPayloadLength(RtpBytes.Length)];
                Buffer.BlockCopy(RtpBytes, 0, SrtpBytes, 0, rtpBytes.Length);
            }

            public string CryptoSuite { get; }

            public byte[] RtpBytes { get; }

            public byte[] SrtpBytes { get; }

            public SrtpSessionContext Context { get; }

            public override string ToString() => CryptoSuite;
        }
    }
}
