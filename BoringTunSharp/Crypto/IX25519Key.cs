using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp.Crypto
{
	public interface IX25519Key
	{
        /// <summary>
        /// The raw byte array data for the key
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// The key converted to Base64
        /// </summary>
        /// <returns>The key in Base64</returns>
        public string Base64();

        /// <summary>
        /// The key converted to hex
        /// </summary>
        /// <returns>The key in hex</returns>
        public string Hex();
    }
}

