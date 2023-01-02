using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp
{
	public class WireGuardTunnel
	{
        #region Constructors

        #endregion
        #region Library User Functions

        #endregion
        #region BoringTun Functions

        #endregion
        #region BoringTun helpers
        
        #endregion
        #region Boringtun Enum's
        /// <summary>
        /// Indicates the operation required from the caller
        /// </summary>
        public enum result_type
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

