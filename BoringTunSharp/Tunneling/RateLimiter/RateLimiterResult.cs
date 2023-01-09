using System;
using System.Text;

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
        public byte[]? Data;
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

        /// <summary>
        /// Convert this object to a string
        /// </summary>
        /// <returns>A multi line string with the result</returns>
        public override string ToString()
        {
            StringBuilder bldr = new StringBuilder();
            bldr.Append("Action required: " + ActionRequired + "\n");
            bldr.Append("Tunnel Index: " + TunnelIndex);
            if(Data != null)
            {
                bldr.Append("\nPacket: " + Convert.ToBase64String(Data));
            }
            return bldr.ToString();
        }
    }
}

