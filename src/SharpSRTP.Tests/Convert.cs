#if !NET5_0_OR_GREATER
using System;

namespace SharpSRTP.Tests
{
    internal static partial class Convert
    {
        internal static byte[] FromHexString(string s)
        {
            if (s == null) throw new ArgumentNullException(nameof(s));
            if ((s.Length & 1) != 0) throw new FormatException("Hex string must have even length.");

            int len = s.Length >> 1;
            var bytes = new byte[len];
            for (int i = 0, bi = 0; bi < len; i += 2, bi++)
            {
                int hi = ParseNibble(s[i]);
                int lo = ParseNibble(s[i + 1]);
                bytes[bi] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        internal static string ToHexString(ReadOnlySpan<byte> bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            char[] c = new char[bytes.Length * 2];
            int ci = 0;
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                c[ci++] = NibbleToHex((b >> 4) & 0xF);
                c[ci++] = NibbleToHex(b & 0xF);
            }
            return new string(c);
        }

        private static int ParseNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new FormatException("Invalid hex character.");
        }

        private static char NibbleToHex(int value)
        {
            return (char)(value < 10 ? ('0' + value) : ('A' + (value - 10)));
        }
    }
}
#endif
