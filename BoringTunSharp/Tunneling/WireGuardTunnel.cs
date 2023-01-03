using System;
using System.Runtime.InteropServices;
using BoringTunSharp.Crypto;
using BoringTunSharp.Tunneling;

namespace BoringTunSharp
{
    public class WireGuardTunnel : IDisposable
    {
        #region Constructors
        /// <summary>
        /// Create a new tunnel
        /// </summary>
        /// <param name="privateKey">The private key for the current machine</param>
        /// <param name="peerPublicKey">The public key for the peer</param>
        /// <param name="presharedKey">The preshared key</param>
        /// <param name="keepAlive">Keep alive time</param>
        /// <param name="index">Tunnel index</param>
        public WireGuardTunnel(IX25519Key privateKey, IX25519Key peerPublicKey, IX25519Key presharedKey, ushort keepAlive, uint index)
        {
            NewTunnel(privateKey.Base64(), peerPublicKey.Base64(), presharedKey.Base64(), keepAlive, index);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="privatePair">A key pair for the current machine</param>
        /// <param name="peerPublicKey">The public key for the peer</param>
        /// <param name="presharedKey">The preshared key</param>
        /// <param name="keepAlive">Keep alive time</param>
        /// <param name="index">Tunnel index</param>
        public WireGuardTunnel(X25519KeyPair privatePair, IX25519Key peerPublicKey, IX25519Key presharedKey, ushort keepAlive, uint index)
        {
            NewTunnel(privatePair.PrivateKey.Base64(), peerPublicKey.Base64(), presharedKey.Base64(), keepAlive, index);
        }

        #endregion
        #region Library User Functions
        /// <summary>
        /// Disposes the tunnel from memory
        /// </summary>
        public unsafe void Dispose()
        {
            tunnel_free(tun);
        }

        /// <summary>
        /// Encapsulate data to send
        /// </summary>
        /// <param name="data">The data to encapsulate</param>
        /// <returns>A wireguard data object. Null if nothing to do.</returns>
        public unsafe WireGuardData? Encapsulate(byte[] data)
        {
            // Create new byte array of the max size of a UDP packet.
            byte[] outputData = new byte[MaxUDPSize];
            wireguard_result wgResult = wireguard_write(tun, data, (uint)data.Length, outputData, (uint)outputData.Length);
            return WireGuardDataBuilder(wgResult, outputData);
        }

        /// <summary>
        /// Decapsulates data from WireGuard peer.
        /// </summary>
        /// <param name="data">Data to decapsulate</param>
        /// <returns>A wireguard data object. Null if nothing to do.</returns>
        public unsafe WireGuardData? Decapsulate(byte[] data)
        {
            // Create new byte array of the max size of a UDP packet.
            byte[] outputData = new byte[MaxUDPSize];
            wireguard_result wgResult = wireguard_read(tun, data, (uint)data.Length, outputData, (uint)outputData.Length);
            return WireGuardDataBuilder(wgResult, outputData);
        }

        /// <summary>
        /// Ticks the WireGuard Tunnel
        /// </summary>
        /// <returns>A wireguard data object. Null if nothing to do.</returns>
        public unsafe WireGuardData? Tick()
        {
            // Create new byte array of the max size of a UDP packet.
            byte[] outputData = new byte[MaxUDPSize];
            wireguard_result wgResult = wireguard_tick(tun, outputData, (uint)outputData.Length);
            return WireGuardDataBuilder(wgResult, outputData);
        }

        /// <summary>
        /// Forces a WireGuard handshake
        /// Needed to initially establish tunnel. May also be needed later to recreate the connection.
        /// </summary>
        /// <returns>A wireguard data object. Null if nothing to do.</returns>
        public unsafe WireGuardData? Handshake()
        {
            // Create new byte array of the max size of a UDP packet.
            byte[] outputData = new byte[MaxUDPSize];
            wireguard_result wgResult = wireguard_force_handshake(tun, outputData, (uint)outputData.Length);
            return WireGuardDataBuilder(wgResult, outputData);
        }

        public unsafe WireGuardTunnelStats GetTunnelStats()
        {
            return wireguard_stats(tun);
        }

        #endregion
        #region BoringTun helpers
        /// <summary>
        /// The maximum size of a UDP packet
        /// </summary>
        private static readonly int MaxUDPSize = 65535;

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

        /// <summary>
        /// Handles the result of a WireGuard function
        /// </summary>
        /// <param name="wgResult"></param>
        /// <param name="outputData"></param>
        /// <returns></returns>
        /// <exception cref="FormatException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        private WireGuardData? WireGuardDataBuilder(wireguard_result wgResult, Byte[] outputData)
        {
            WireGuardData.Destination resultDst;
            // Determine what to do based on the result of the operation:
            switch (wgResult.op)
            {
                default:
                    throw new FormatException("Unknown BoringTun Result");
                case result_type.WIREGUARD_DONE:
                    return null;
                case result_type.WIREGUARD_ERROR:
                    throw new InvalidOperationException("Failed to process WireGuard data.");
                case result_type.WRITE_TO_NETWORK:
                    resultDst = WireGuardData.Destination.Network;
                    break;
                case result_type.WRITE_TO_TUNNEL_IPV4:
                    resultDst = WireGuardData.Destination.Tunnel_IPv4;
                    break;
                case result_type.WRITE_TO_TUNNEL_IPV6:
                    resultDst = WireGuardData.Destination.Tunnel_IPv6;
                    break;
            }
            // Resize the array to the size we want now:
            Array.Resize(ref outputData, (int)wgResult.size);
            // Return the result:
            return new WireGuardData(outputData, resultDst);
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
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern object?* new_tunnel(string static_private, string server_static_public, string preshared_key, ushort keep_alive, uint index);

        /// <summary>
        /// Deallocate a tunnel
        /// </summary>
        /// <param name="tunnel">The tunnel to deallocate</param>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern void tunnel_free(object* tunnel);

        /// <summary>
        /// Encapsulate data with WireGuard
        /// </summary>
        /// <param name="tunnel"></param>
        /// <param name="src"></param>
        /// <param name="src_size"></param>
        /// <param name="dst"></param>
        /// <param name="dst_size"></param>
        /// <returns></returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern wireguard_result wireguard_write(object* tunnel, byte[] src, uint src_size, byte[] dst, uint dst_size);

        /// <summary>
        /// Decapsulate data from WireGuard
        /// </summary>
        /// <param name="tunnel"></param>
        /// <param name="src"></param>
        /// <param name="src_size"></param>
        /// <param name="dst"></param>
        /// <param name="dst_size"></param>
        /// <returns></returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern wireguard_result wireguard_read(object* tunnel, byte[] src, uint src_size, byte[] dst, uint dst_size);

        /// <summary>
        /// Tick the WireGuard tunnel
        /// </summary>
        /// <param name="tunnel"></param>
        /// <param name="dst"></param>
        /// <param name="dst_size"></param>
        /// <returns></returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern wireguard_result wireguard_tick(object* tunnel, byte[] dst, uint dst_size);

        /// <summary>
        /// Force a WireGuard Handshake
        /// </summary>
        /// <param name="tunnel"></param>
        /// <param name="dst"></param>
        /// <param name="dst_size"></param>
        /// <returns></returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern wireguard_result wireguard_force_handshake(object* tunnel, byte[] dst, uint dst_size);

        /// <summary>
        /// Gets the statistics about the WireGuard tunnel
        /// </summary>
        /// <param name="tunnel">The tunnel to get the stats from</param>
        /// <returns>A struct with stats</returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern WireGuardTunnelStats wireguard_stats(object* tunnel);

        #endregion
        #region Boringtun Structs
        /// <summary>
        /// The result of the operation
        /// </summary>
        private struct wireguard_result
        {
            public result_type op;
            public IntPtr size;
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

