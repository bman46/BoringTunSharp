using System;
using System.Text;

namespace BoringTunSharp.Tunneling
{
	public struct WireGuardTunnelStats
	{
        /// <summary>
        /// The time since the last handshake
        /// </summary>
        /// <remarks>Will be -1 if no handshake occurred</remarks>
        public long time_since_last_handshake;
        /// <summary>
        /// The amount of bytes transmitted
        /// </summary>
        public UIntPtr tx_bytes;
        /// <summary>
        /// The amount of bytes received
        /// </summary>
        public UIntPtr rx_bytes;
        /// <summary>
        /// The estimated amount of loss
        /// </summary>
        public float estimated_loss;
        /// <summary>
        /// Rtt estimated on time it took to complete latest initiated handshake in ms
        /// </summary>
        public uint estimated_rtt;

        /// <summary>
        /// Generates a string with this classes data
        /// </summary>
        /// <returns>A string with data</returns>
        public override string ToString()
        {
            StringBuilder bldr = new StringBuilder();
            bldr.Append("Time since handshake: " + time_since_last_handshake + "\n");
            bldr.Append("Tx Bytes: " + tx_bytes + "\n");
            bldr.Append("Rx Bytes: " + rx_bytes + "\n");
            bldr.Append("Estimated Loss: " + estimated_loss + "\n");
            bldr.Append("Estimated RTT: " + estimated_rtt);
            return bldr.ToString();
        }
    }
}

