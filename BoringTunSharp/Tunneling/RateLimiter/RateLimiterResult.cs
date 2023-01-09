using System;
namespace BoringTunSharp.Tunneling.RateLimiter
{
	public class RateLimiterResult
	{
        /// <summary>
        /// Required action for this packet
        /// </summary>
        public Actions ActionRequired;
        /// <summary>
        /// The tunnel index
        /// </summary>
        public int TunnelIndex;
        /// <summary>
        /// The data to perform an action on
        /// </summary>
        public byte[] Data;
        /// <summary>
        /// The actions to perform with the data
        /// </summary>
        public enum Actions
        {
            /// <summary>
            /// Send the data to the peer WireGuard Server
            /// </summary>
            Network = 0,
            /// <summary>
            /// Send the data to the tunnel device (IPv4)
            /// </summary>
            Tunnel_IPv4 = 1,
            /// <summary>
            /// Send the data to the tunnel device (IPv6)
            /// </summary>
            Tunnel_IPv6 = 2,
            /// <summary>
            /// No action is required
            /// </summary>
            No_Action = 3
        }
    }
}

