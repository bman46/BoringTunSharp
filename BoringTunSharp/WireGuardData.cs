using System;
namespace BoringTunSharp
{
	public class WireGuardData
    {
		public WireGuardData(byte[] data, Destination sendTo)
		{
			Data = data;
			SendTo = sendTo;
		}
		/// <summary>
		/// The data to send
		/// </summary>
		public byte[] Data;
		/// <summary>
		/// Where should the packet be sent to?
		/// </summary>
		public Destination SendTo;
		/// <summary>
		/// The options of where to send the data
		/// </summary>
		public enum Destination
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
            Tunnel_IPv6 = 2
        }
	}
}

