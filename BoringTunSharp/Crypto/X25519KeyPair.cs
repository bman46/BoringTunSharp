using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using BoringTunSharp.Crypto;

namespace BoringTunSharp
{
	public class X25519KeyPair
	{
        /// <summary>
        /// Create a key pair from an existing key
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="privateKey">private key</param>
        public X25519KeyPair(X25519PublicKey publicKey, X25519PrivateKey privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <summary>
        /// Create a key pair from an existing private key
        /// </summary>
        /// <param name="privateKey">The private key to use</param>
        public X25519KeyPair(X25519PrivateKey privateKey)
        {
            X25519PublicKey publicKey = new X25519PublicKey(privateKey);
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <summary>
        /// Generate a new key pair
        /// </summary>
        public X25519KeyPair()
        {
            X25519PrivateKey privateKey = new X25519PrivateKey();
            X25519PublicKey publicKey = new X25519PublicKey(privateKey);
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <summary>
        /// Store the public key
        /// </summary>
        private X25519PublicKey _publicKey;

        /// <summary>
        /// Store the private key
        /// </summary>
        private X25519PrivateKey _privateKey;

        /// <summary>
        /// The public key
        /// </summary>
        public X25519PublicKey PublicKey
        {
            get
            {
                return _publicKey;
            }
        }

        /// <summary>
        /// The private key
        /// </summary>
		public X25519PrivateKey PrivateKey
        {
            get
            {
                return _privateKey;
            }
        }
    }
}

