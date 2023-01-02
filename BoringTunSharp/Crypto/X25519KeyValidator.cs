using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp.Crypto
{
	public class X25519KeyValidator
	{
		/// <summary>
		/// Checks to see if a key is valid or not
		/// </summary>
		/// <param name="key">The key to test</param>
		/// <returns>True if valid, false if not</returns>
		public static bool IsKeyVaild(byte[] key)
		{
			string base64Key = Convert.ToBase64String(key);
			return check_base64_encoded_x25519_key(base64Key) != 0;
		}

		/// <summary>
		/// BoringTun function to validate key
		/// </summary>
		/// <param name="base64Key">The key to validate</param>
		/// <returns>0 if not valid</returns>
        [DllImport("libboringtun", CallingConvention = CallingConvention.Cdecl)]
        private static extern int check_base64_encoded_x25519_key(string base64Key);
    }
}

