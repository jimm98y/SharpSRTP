using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace SharpSRTP.SRTP
{
    internal static class BinaryExtensions
    {
        public static void Xor(Span<byte> data, ReadOnlySpan<byte> other)
        {
            int i = 0;

            for (; i <= data.Length - 8; i += 8)
            {
                Xor64(data.Slice(i, 8), other.Slice(i, 8));
            }

            if (i <= data.Length - 4)
            {
                Xor32(data.Slice(i, 4), other.Slice(i, 4));
                i += 4;
            }

            if (i <= data.Length - 2)
            {
                Xor16(data.Slice(i, 2), other.Slice(i, 2));
                i += 2;
            }

            if (i < data.Length)
            {
                data[i] ^= other[i];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor128(Span<byte> data, ReadOnlySpan<byte> other)
        {
            Xor64(data, other);
            Xor64(data.Slice(8), other.Slice(8));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor64(Span<byte> data, ReadOnlySpan<byte> other)
        {
            Xor64(data, BinaryPrimitives.ReadUInt64BigEndian(other));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor64(Span<byte> data, ulong other)
        {
            BinaryPrimitives.WriteUInt64BigEndian(data, BinaryPrimitives.ReadUInt64BigEndian(data) ^ other);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor32(Span<byte> data, ReadOnlySpan<byte> other)
        {
            Xor32(data, BinaryPrimitives.ReadUInt32BigEndian(other));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor32(Span<byte> data, uint other)
        {
            BinaryPrimitives.WriteUInt32BigEndian(data, BinaryPrimitives.ReadUInt32BigEndian(data) ^ other);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor16(Span<byte> data, ReadOnlySpan<byte> other)
        {
            Xor16(data, BinaryPrimitives.ReadUInt16LittleEndian(other));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor16(Span<byte> data, ushort other)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(data, (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(data) ^ other));
        }
    }
}
