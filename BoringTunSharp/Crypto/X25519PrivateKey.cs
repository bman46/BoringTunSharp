using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp.Crypto
{
    public class X25519PrivateKey : IX25519Key
    {
        /// <summary>
        /// Creates a new x25519 key.
        /// </summary>
        public X25519PrivateKey()
        {
            x25519_key key = x25519_secret_key();
            data = key.key;
        }

        /// <summary>
        /// Creates a new instance of this class from
        /// </summary>
        /// <param name="existingKey">The existing key to use</param>
        /// <exception cref="ArgumentException">Thrown when key is invalid</exception>
        public X25519PrivateKey(byte[] existingKey)
        {
            if (!X25519KeyValidator.IsKeyVaild(existingKey))
            {
                throw new ArgumentException("Invalid key!");
            }
            data = existingKey;
        }

        /// <summary>
        /// Stores the raw key
        /// </summary>
        private byte[] data;

        #region Interface
        /// <summary>
        /// Key in byte form
        /// </summary>
        public byte[] Data
        {
            get
            {
                return data;
            }
        }

        /// <summary>
        /// Key in Base64 form
        /// </summary>
        /// <returns></returns>
        public string Base64()
        {
            return Convert.ToBase64String(Data);
        }

        /// <summary>
        /// Key in hex format
        /// </summary>
        /// <returns></returns>
        public string Hex()
        {
            return Convert.ToHexString(Data);
        }
        #endregion
        #region BoringTun
        /// <summary>
        /// Generates a fresh x25519 secret key
        /// </summary>
        /// <returns>A x25519 secret key</returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static extern x25519_key x25519_secret_key();
        #endregion
    }
}

