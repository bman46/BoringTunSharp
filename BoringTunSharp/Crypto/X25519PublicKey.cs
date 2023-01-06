using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp.Crypto
{
    public class X25519PublicKey : IX25519Key
    {
        /// <summary>
        /// Generate a public key from a private key
        /// </summary>
        /// <param name="privateKey"></param>
        public X25519PublicKey(X25519PrivateKey privateKey)
        {
            x25519_key key = new x25519_key();
            key.key = privateKey.Data;
            data = x25519_public_key(key).key;
        }
        /// <summary>
        /// Set this key to the byte array of an existing key
        /// </summary>
        /// <param name="existingPublicKey">The existing public key</param>
        /// <exception cref="ArgumentException">Thrown when the key is not valid</exception>
        public X25519PublicKey(byte[] existingPublicKey)
        {
            if (!X25519KeyValidator.IsKeyVaild(existingPublicKey))
            {
                throw new ArgumentException("Invalid key!");
            }
            data = existingPublicKey;
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
            return BitConverter.ToString(Data).Replace("-", string.Empty);
        }
        #endregion
        #region BoringTun
        /// <summary>
        /// Generates a new public key from a secret key
        /// </summary>
        /// <param name="secretKey">The key to derive from</param>
        /// <returns>A public key</returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static extern x25519_key x25519_public_key(x25519_key secretKey);
        #endregion
    }
}