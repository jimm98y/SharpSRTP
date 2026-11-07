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

#if NET8_0_OR_GREATER
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
using Bytes = System.Span<byte>;
#else
using ReadOnlyBytes = System.ArraySegment<byte>;
using Bytes = byte[];
#endif

namespace SharpSRTP.SRTP
{
    public interface ISrtpContext
    {
        int CalculateRequiredSrtpPayloadLength(int rtpLen);
        int ProtectRtp(ReadOnlyBytes input, Bytes output, out int outputBufferLength);
        int UnprotectRtp(ReadOnlyBytes input, Bytes output, out int outputBufferLength);
        int CalculateRequiredSrtcpPayloadLength(int rtpLen);
        int ProtectRtcp(ReadOnlyBytes input, Bytes output, out int outputBufferLength);
        int UnprotectRtcp(ReadOnlyBytes input, Bytes output, out int outputBufferLength);

#if NET8_0_OR_GREATER
        // What netstandard2.0 offers as well, so that a library built against it runs here too.

        int ProtectRtp(System.ArraySegment<byte> input, byte[] output, out int outputBufferLength)
            => ProtectRtp((ReadOnlyBytes)input, (Bytes)SrtpOverloads.NotNull(output), out outputBufferLength);

        int UnprotectRtp(System.ArraySegment<byte> input, byte[] output, out int outputBufferLength)
            => UnprotectRtp((ReadOnlyBytes)input, (Bytes)SrtpOverloads.NotNull(output), out outputBufferLength);

        int ProtectRtcp(System.ArraySegment<byte> input, byte[] output, out int outputBufferLength)
            => ProtectRtcp((ReadOnlyBytes)input, (Bytes)SrtpOverloads.NotNull(output), out outputBufferLength);

        int UnprotectRtcp(System.ArraySegment<byte> input, byte[] output, out int outputBufferLength)
            => UnprotectRtcp((ReadOnlyBytes)input, (Bytes)SrtpOverloads.NotNull(output), out outputBufferLength);
#endif
    }

    public static class SrtpContextExtensions
    {
        public static int ProtectRtp(this ISrtpContext context, Bytes payload, int length, out int outputBufferLength)
            => context.ProtectRtp(payload.Slice(0, length), payload, out outputBufferLength);

        public static int UnprotectRtp(this ISrtpContext context, Bytes payload, int length, out int outputBufferLength)
            => context.UnprotectRtp(payload.Slice(0, length), payload, out outputBufferLength);

        public static int ProtectRtcp(this ISrtpContext context, Bytes payload, int length, out int outputBufferLength)
            => context.ProtectRtcp(payload.Slice(0, length), payload, out outputBufferLength);

        public static int UnprotectRtcp(this ISrtpContext context, Bytes payload, int length, out int outputBufferLength)
            => context.UnprotectRtcp(payload.Slice(0, length), payload, out outputBufferLength);

#if NET8_0_OR_GREATER
        // What netstandard2.0 offers as well, so that a library built against it runs here too.

        public static int ProtectRtp(this ISrtpContext context, byte[] payload, int length, out int outputBufferLength)
            => context.ProtectRtp(new System.ArraySegment<byte>(payload, 0, length), payload, out outputBufferLength);

        public static int UnprotectRtp(this ISrtpContext context, byte[] payload, int length, out int outputBufferLength)
            => context.UnprotectRtp(new System.ArraySegment<byte>(payload, 0, length), payload, out outputBufferLength);

        public static int ProtectRtcp(this ISrtpContext context, byte[] payload, int length, out int outputBufferLength)
            => context.ProtectRtcp(new System.ArraySegment<byte>(payload, 0, length), payload, out outputBufferLength);

        public static int UnprotectRtcp(this ISrtpContext context, byte[] payload, int length, out int outputBufferLength)
            => context.UnprotectRtcp(new System.ArraySegment<byte>(payload, 0, length), payload, out outputBufferLength);
#endif
    }

#if NET8_0_OR_GREATER
    internal static class SrtpOverloads
    {
        // netstandard2.0 refuses a missing output, where a span would quietly be an empty one
        public static byte[] NotNull(byte[] output) => output ?? throw new System.ArgumentNullException(nameof(output));
    }
#endif
}
