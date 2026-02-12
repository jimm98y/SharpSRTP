using BenchmarkDotNet.Running;

namespace SharpSRTP.Benchmarks
{
    static class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run(typeof(Program).Assembly, config: new Config());
        }
    }
}
