using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace BoringTunSharp
{
	public class X25519KeyPair
	{
        #region Constructors
        /// <summary>
        /// Generate a new x25519 key pair
        /// </summary>
        public X25519KeyPair()
        {
            privateKey = GenerateSecretKey();
            publicKey = GeneratePublicKey(privateKey);
        }
        /// <summary>
        /// Create a new x25519 key pair from an public and private key
        /// </summary>
        /// <param name="privateKey">The private x25519 key</param>
        /// <param name="publicKey">The public x25519 key</param>
        public X25519KeyPair(byte[] privateKey, byte[] publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        /// <summary>
        /// Generate a x25519 key pair from an existing private key
        /// </summary>
        /// <param name="privateKey">The private x25519 key</param>
        public X25519KeyPair(byte[] privateKey)
        {
            this.privateKey = privateKey;
            publicKey = GeneratePublicKey(privateKey);
        }
        #endregion
        #region Keys
        /// <summary>
        /// A x25519 public key
        /// </summary>
        public byte[] publicKey;

        /// <summary>
        /// A x25519 private key
        /// </summary>
        public byte[] privateKey;
        #endregion Keys

        /// <summary>
        /// The public key in base64 form
        /// </summary>
        /// <returns>A base64 string of the public key</returns>
        public string PublicKeyBase64()
        {
            return KeyToBase64(publicKey);
        }

        /// <summary>
        /// The private key in base64 form
        /// </summary>
        /// <returns>A base64 string of the private key</returns>
        public string PrivateKeyBase64()
        {
            return KeyToBase64(privateKey);
        }

        /// <summary>
        /// The public key in hex form
        /// </summary>
        /// <returns>A hex string of the public key</returns>
        public string PublicKeyHex()
        {
            return KeyToHex(publicKey);
        }

        /// <summary>
        /// The private key in hex form
        /// </summary>
        /// <returns>A hex string of the private key</returns>
        public string PrivateKeyHex()
        {
            return KeyToHex(privateKey);
        }

        /// <summary>
        /// Converts a byte[] key to base64
        /// </summary>
        /// <param name="key">The key to convert</param>
        /// <returns>The key in base64 string</returns>
        public static string KeyToBase64(byte[] key)
        {
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Converts a byte[] key to hex
        /// </summary>
        /// <param name="key">The key to convert</param>
        /// <returns>The key in hex string</returns>
        public static string KeyToHex(byte[] key)
        {
            return Convert.ToHexString(key);
        }

        /// <summary>
        /// Generates a fresh x25519 secret key
        /// </summary>
        /// <returns></returns>
        public static byte[] GenerateSecretKey()
        {
            return x25519_secret_key().key;
        }

        /// <summary>
        /// Generates a public x25519 key from a secret x25519 key
        /// </summary>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public static byte[] GeneratePublicKey(byte[] secretKey) {
            x25519_key pKey = new x25519_key();
            pKey.key = secretKey;
            return x25519_public_key(pKey).key;
        }

        #region BoringTun Library Code
        /// <summary>
        /// key struct from libboringtun
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct x25519_key
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] key;
        }

        /// <summary>
        /// Generates a fresh x25519 secret key
        /// </summary>
        /// <returns>A x25519 secret key</returns>
        [DllImport("libboringtun", CallingConvention = CallingConvention.Cdecl)]
        private static extern x25519_key x25519_secret_key();

        /// <summary>
        /// Computes an x25519 public key from a secret key
        /// </summary>
        /// <param name="private_key">A private x25519 key to generate a public key from</param>
        /// <returns>A public x25519 key</returns>
        [DllImport("libboringtun", CallingConvention = CallingConvention.Cdecl)]
        private static extern x25519_key x25519_public_key(x25519_key private_key);
        #endregion
    }
}

