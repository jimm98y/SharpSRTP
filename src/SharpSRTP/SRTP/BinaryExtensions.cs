using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
#if NET8_0_OR_GREATER
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
#endif

namespace SharpSRTP.SRTP
{
    internal static class BinaryExtensions
    {
        public static void Xor(Span<byte> data, ReadOnlySpan<byte> other)
        {
            int i = 0;

#if NET8_0_OR_GREATER
            ref byte dRef = ref MemoryMarshal.GetReference(data);
            ref byte oRef = ref MemoryMarshal.GetReference(other);

            if (Vector512.IsHardwareAccelerated)
            {
                for (; i <= data.Length - 64; i += 64)
                    (Vector512.LoadUnsafe(ref Unsafe.Add(ref dRef, i)) ^
                     Vector512.LoadUnsafe(ref Unsafe.Add(ref oRef, i)))
                        .StoreUnsafe(ref Unsafe.Add(ref dRef, i));
            }

            if (Vector256.IsHardwareAccelerated)
            {
                for (; i <= data.Length - 32; i += 32)
                    (Vector256.LoadUnsafe(ref Unsafe.Add(ref dRef, i)) ^
                     Vector256.LoadUnsafe(ref Unsafe.Add(ref oRef, i)))
                        .StoreUnsafe(ref Unsafe.Add(ref dRef, i));
            }

            if (Vector128.IsHardwareAccelerated)
            {
                for (; i <= data.Length - 16; i += 16)
                    (Vector128.LoadUnsafe(ref Unsafe.Add(ref dRef, i)) ^
                     Vector128.LoadUnsafe(ref Unsafe.Add(ref oRef, i)))
                        .StoreUnsafe(ref Unsafe.Add(ref dRef, i));
            }
#endif

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
#if NET8_0_OR_GREATER
            var result = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(data)) ^
                         Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(other));
            result.StoreUnsafe(ref MemoryMarshal.GetReference(data));
#else
            Xor64(data, other);
            Xor64(data.Slice(8), other.Slice(8));
#endif
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
