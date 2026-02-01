using Org.BouncyCastle.Tls;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SharpSRTP
{
    internal static class Throw
    {
        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ArgumentNullException(string paramName = null)
            => throw new global::System.ArgumentNullException(paramName: paramName);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ArgumentException(string message, string paramName = null)
            => throw new global::System.ArgumentException(message: message, paramName: paramName);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ArgumentOutOfRangeException(string message, string paramName)
            => throw new global::System.ArgumentOutOfRangeException(paramName: paramName, message: message);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void InvalidOperationException(string message = null)
            => throw new global::System.InvalidOperationException(message: message);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void NotSupportedException(string message = null)
            => throw new global::System.NotSupportedException(message: message);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void FormatException(string message = null)
            => throw new global::System.FormatException(message: message);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void TlsFatalAlert(short alertDescription)
            => throw new TlsFatalAlert(alertDescription: alertDescription);

        [DoesNotReturn]
        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void CryptographicException(int hr)
            => throw new CryptographicException(hr: hr);

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfNull([NotNull] object argument, [CallerArgumentExpression(nameof(argument))] string paramName = null)
        {
#if NET8_0_OR_GREATER
            global::System.ArgumentNullException.ThrowIfNull(argument, paramName);
#else
            if (argument is null)
            {
                ArgumentNullException(paramName);
            }
#endif
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfNullOrEmpty([NotNull] string argument, [CallerArgumentExpression(nameof(argument))] string paramName = null)
        {
#if NET8_0_OR_GREATER
            global::System.ArgumentException.ThrowIfNullOrEmpty(argument, paramName);
#else
            if (argument is null)
            {
                ArgumentNullException(paramName);
            }

            if (argument.Length == 0)
            {
                ArgumentException("The value cannot be an empty string.", paramName);
            }
#endif
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfEmpty<T>(ReadOnlySpan<T> value, [CallerArgumentExpression(nameof(value))] string paramName = null)
        {
            if (value.IsEmpty)
            {
                ArgumentException($"'{paramName}' should not be empty.", paramName);
            }
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfFalse(bool value, [CallerArgumentExpression(nameof(value))] string paramName = null)
        {
            if (!value)
            {
                ArgumentOutOfRangeException($"'{paramName}' should not be 'false'.", paramName);
            }
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowIfNotEqual<T>(T value, T other, [CallerArgumentExpression(nameof(value))] string paramName = null)
            where T : IEquatable<T>
        {
            if (!value.Equals(other))
            {
                ArgumentOutOfRangeException($"'{paramName}' should be '{other}'.", paramName);
            }
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfNotEqual<T>(T value, T other, [CallerArgumentExpression(nameof(value))] string paramName = null)
            where T : IEquatable<T>
        {
#if NET8_0_OR_GREATER
            global::System.ArgumentOutOfRangeException.ThrowIfNotEqual<T>(value, other, paramName);
#else
            if (!value.Equals(other))
            {
                ArgumentOutOfRangeException($"'{paramName}' must be '{other}'.", paramName);
            }
#endif
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfLessThan<T>(T value, T other, [CallerArgumentExpression(nameof(value))] string paramName = null)
            where T : IComparable<T>
        {
#if NET8_0_OR_GREATER
            global::System.ArgumentOutOfRangeException.ThrowIfLessThan<T>(value, other, paramName);
#else
            if (value.CompareTo(other) < 0)
            {
                ArgumentOutOfRangeException($"'{paramName}' cannot be less than '{other}'.", paramName);
            }
#endif
        }

        [StackTraceHidden]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void IfGreaterThan<T>(T value, T other, [CallerArgumentExpression(nameof(value))] string paramName = null)
            where T : IComparable<T>
        {
#if NET8_0_OR_GREATER
            global::System.ArgumentOutOfRangeException.ThrowIfGreaterThan<T>(value, other, paramName);
#else
            if (value.CompareTo(other) < 0)
            {
                ArgumentOutOfRangeException($"'{paramName}' cannot be greater than '{other}'.", paramName);
            }
#endif
        }
    }
}
