using System;
using System.Runtime.CompilerServices;

internal static partial class PolyfillExtensions
{
#if !NET8_0_OR_GREATER
    extension(GC)
    {
        /// <summary>
        /// Allocate an array while skipping zero-initialization if possible.
        /// </summary>
        /// <typeparam name="T">Specifies the type of the array element.</typeparam>
        /// <param name="length">Specifies the length of the array.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)] // forced to ensure no perf drop for small memory buffers (hot path)
        public static T[] AllocateUninitializedArray<T>(int length) // T[] rather than T?[] to match `new T[length]` behavior
        {
            return new T[length];
        }
    }

    extension<T>(ArraySegment<T> source)
    {
        public ArraySegment<T> Slice(int index)
        {
            if (source.Array == null)
            {
                throw new InvalidOperationException();
            }

            if ((uint)index > (uint)source.Count)
            {
                throw new ArgumentOutOfRangeException();
            }

            return new ArraySegment<T>(source.Array, source.Offset + index, source.Count - index);
        }

        public ArraySegment<T> Slice(int index, int count)
        {
            if (source.Array == null)
            {
                throw new InvalidOperationException();
            }

            if ((uint)index > (uint)source.Count || (uint)count > (uint)(source.Count - index))
            {
                throw new ArgumentOutOfRangeException();
            }

            return new ArraySegment<T>(source.Array, source.Offset + index, count);
        }
    }
#endif

    public static ArraySegment<T> AsArraySegment<T>(this T[] array) => array != null ? new ArraySegment<T>(array) : default(ArraySegment<T>);

    public static ArraySegment<T> AsArraySegment<T>(this T[] array, int count) => array != null ? new ArraySegment<T>(array, array.Length - count, count) : default(ArraySegment<T>);

    public static ArraySegment<T> AsArraySegment<T>(this T[] array, int offset, int count) => array != null ? new ArraySegment<T>(array, offset, count) : default(ArraySegment<T>);
}
