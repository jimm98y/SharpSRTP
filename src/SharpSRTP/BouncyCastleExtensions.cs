using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Runtime.CompilerServices;

public static class BouncyCastleExtensions
{
    extension(KeyParameter)
    {
#if NET8_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter Create(ReadOnlyMemory<byte> key)
        {
            return new KeyParameter(key.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter Create(ReadOnlySpan<byte> key)
        {
            return new KeyParameter(key);
        }
#else
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter Create(ReadOnlyMemory<byte> memory)
        {
            if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment))
            {
                return KeyParameter.Create(segment);
            }
            // Fallback for non-array-backed memory
            return new KeyParameter(memory.ToArray());
        }
#endif
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter Create(ArraySegment<byte> key)
        {
            return new KeyParameter(key.Array, key.Offset, key.Count);
        }
    }
}
