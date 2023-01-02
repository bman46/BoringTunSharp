using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp.Crypto
{
    /// <summary>
    /// Internal Type for the BoringTun x25519_key struct.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct x25519_key
    {
        /// <summary>
        /// Key in byte array format
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] key;
    }
}

