using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp
{
    public class WireGuardTunnel : IDisposable
    {
        #region Constructors
        public WireGuardTunnel(string privateKey, string peerPublicKey, string presharedKey, ushort keepAlive, uint index)
        {
            NewTunnel(privateKey, peerPublicKey, presharedKey, keepAlive, index);
        }
        #endregion
        #region Library User Functions
        public void Dispose()
        {
            // TODO: dispose of tunnel
            //throw new NotImplementedException();
        }
        #endregion
        #region BoringTun helpers
        /// <summary>
        /// An instance of the wireguard tunnel
        /// </summary>
        private unsafe object* tun;

        /// <summary>
        /// Creates a new tunnel
        /// </summary>
        /// <param name="static_private">Base64 private key</param>
        /// <param name="server_static_public">Base64 public key from server</param>
        /// <param name="preshared_key">Base64 preshared key</param>
        /// <param name="keep_alive">keep alive interval</param>
        /// <param name="index">24bit index prefix to be used for session indexes</param>
        /// <exception cref="InvalidOperationException">Boringtun failed to create a new tunnel</exception>
        private unsafe void NewTunnel(string static_private, string server_static_public, string preshared_key, ushort keep_alive, uint index)
        {
            // Create a new tunnel:
            object?* newTun = new_tunnel(static_private, server_static_public, preshared_key, keep_alive, index);
            // Ensure tunnel is not null:
            if (newTun == null)
            {
                throw new InvalidOperationException("Failed to create new tunnel");
            }
            tun = (object*) newTun;
        }
        #endregion
        #region BoringTun Functions

        /// <summary>
        /// Allocate a new tunnel
        /// </summary>
        /// <param name="static_private">Base64 private key</param>
        /// <param name="server_static_public">Base64 public key from server</param>
        /// <param name="preshared_key">Base64 preshared key</param>
        /// <param name="keep_alive">keep alive interval</param>
        /// <param name="index">24bit index prefix to be used for session indexes</param>
        /// <returns>Null if failed</returns>
        [DllImport("libboringtun", CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern object?* new_tunnel(string static_private, string server_static_public, string preshared_key, ushort keep_alive, uint index);

        #endregion
        #region Boringtun Structs
        /// <summary>
        /// The result of the operation
        /// </summary>
        private struct wireguard_result
        {
            result_type op;
            IntPtr size;
        };
        #endregion
        #region Boringtun Enum's
        /// <summary>
        /// Indicates the operation required from the caller
        /// </summary>
        private enum result_type
        {
            /// <summary>
            /// No operation is required.
            /// </summary>
            WIREGUARD_DONE = 0,
            /// <summary>
            /// Write dst buffer to network. Size indicates the number of bytes to write.
            /// </summary>
            WRITE_TO_NETWORK = 1,
            /// <summary>
            /// Some error occurred, no operation is required. Size indicates error code.
            /// </summary>
            WIREGUARD_ERROR = 2,
            /// <summary>
            /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
            /// </summary>
            WRITE_TO_TUNNEL_IPV4 = 4,
            /// <summary>
            /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
            /// </summary>
            WRITE_TO_TUNNEL_IPV6 = 6
        }
        #endregion
    }
}

