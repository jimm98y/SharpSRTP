using System;
using System.Runtime.CompilerServices;

namespace SharpSRTP;

internal static class BytesExtensions
{
#if NET8_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> AsBytes(this Span<byte> bytes) => bytes;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> AsSpan(this Span<byte> bytes) => bytes;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> AsSpan(this Span<byte> bytes, int start) => bytes.Slice(start);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> AsSpan(this Span<byte> bytes, int start, int length) => bytes.Slice(start, length);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ReadOnlySpan<byte> AsBytes(this ReadOnlySpan<byte> bytes) => bytes;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ReadOnlySpan<byte> AsSpan(this ReadOnlySpan<byte> bytes) => bytes;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ReadOnlySpan<byte> AsSpan(this ReadOnlySpan<byte> bytes, int start) => bytes.Slice(start);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ReadOnlySpan<byte> AsSpan(this ReadOnlySpan<byte> bytes, int start, int length) => bytes.Slice(start, length);
#else
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] AsBytes(this ReadOnlySpan<byte> bytes) => bytes.ToArray();
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] AsBytes(this Span<byte> bytes) => bytes.ToArray();
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> Slice(this byte[] bytes, int start, int length) => bytes.AsSpan(start, length);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Span<byte> Slice(this byte[] bytes, int start) => bytes.AsSpan(start, bytes.Length - start);
#endif
}
