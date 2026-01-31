using System;
using System.Runtime.CompilerServices;

#if !NET8_0_OR_GREATER
internal sealed class SkipLocalsInitAttribute : Attribute { }

internal sealed class DoesNotReturnAttribute : Attribute { }

internal sealed class NotNullAttribute : Attribute { }

[AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
internal sealed class CallerArgumentExpressionAttribute : Attribute
{
    public CallerArgumentExpressionAttribute(string parameterName)
    {
        ParameterName = parameterName;
    }

    public string ParameterName { get; }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Constructor | AttributeTargets.Struct, Inherited = false)]
public sealed class StackTraceHiddenAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="StackTraceHiddenAttribute"/> class.
    /// </summary>
    public StackTraceHiddenAttribute() { }
}

internal static partial class GC
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
#endif
