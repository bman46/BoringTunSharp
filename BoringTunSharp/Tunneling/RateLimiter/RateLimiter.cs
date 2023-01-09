using System;
using System.Runtime.InteropServices;
using BoringTunSharp.Crypto;
using static BoringTunSharp.WireGuardTunnel;

namespace BoringTunSharp.Tunneling.RateLimiter
{
    public class RateLimiter : IDisposable
    {
        #region Constructors
        /// <summary>
        /// Create a new rate limiter
        /// </summary>
        /// <param name="PublicKey"></param>
        /// <param name="limit"></param>
        public RateLimiter(IX25519Key PublicKey, UInt64 limit)
        {
            NewRateLimiter(PublicKey.Base64(), limit);
        }

        /// <summary>
        /// Create a new rate limiter
        /// </summary>
        /// <param name="selfKeyPair"></param>
        /// <param name="limit"></param>
        public RateLimiter(X25519KeyPair selfKeyPair, UInt64 limit)
        {
            NewRateLimiter(selfKeyPair.PublicKey.Base64(), limit);
        }
        #endregion

        /// <summary>
        /// The rate limiter pointer
        /// </summary>
        private unsafe object* rateLimiter;

        /// <summary>
        /// Dispose of the rate limiter
        /// </summary>
        public unsafe void Dispose()
        {
            rate_limiter_free(rateLimiter);
        }

        /// <summary>
        /// Reset the rate limiter counts
        /// Suggested to call ~1 per second
        /// </summary>
        public unsafe void ResetCount()
        {
            wireguard_reset_count(rateLimiter);
        }

        /// <summary>
        /// Process a packet
        /// </summary>
        /// <param name="packet">The packet to process</param>
        /// <returns>A rate limiter result</returns>
        /// <exception cref="FormatException">Returned when the result from BoringTun is unknown.</exception>
        /// <exception cref="InvalidOperationException">Returned when the packet causes an error.</exception>
        public unsafe RateLimiterResult ProcessPacket(byte[] packet)
        {
            byte[] outputData = new byte[MaxUDPSize];
            WireguardVerifyResult result = wireguard_verify_packet(rateLimiter, packet, (uint) packet.Length, outputData, (uint) outputData.Length);

            RateLimiterResult rateLimiterResult = new RateLimiterResult();
            switch (result.result.op)
            {
                default:
                    throw new FormatException("Unknown BoringTun Result");
                case result_type.WIREGUARD_DONE:
                    rateLimiterResult.ActionRequired = RateLimiterResult.Actions.No_Action;
                    break;
                case result_type.WIREGUARD_ERROR:
                    throw new InvalidOperationException("Failed to process WireGuard data.");
                case result_type.WRITE_TO_NETWORK:
                    rateLimiterResult.ActionRequired = RateLimiterResult.Actions.Network;
                    rateLimiterResult.Data = outputData;
                    break;
                case result_type.WRITE_TO_TUNNEL_IPV4:
                    rateLimiterResult.ActionRequired = RateLimiterResult.Actions.Tunnel_IPv4;
                    rateLimiterResult.Data = outputData;
                    break;
                case result_type.WRITE_TO_TUNNEL_IPV6:
                    rateLimiterResult.ActionRequired = RateLimiterResult.Actions.Tunnel_IPv6;
                    rateLimiterResult.Data = outputData;
                    break;
            }
            if(result.idx >= 0)
            {
                rateLimiterResult.TunnelIndex = result.idx;
            }
            return rateLimiterResult;
        }

        /// <summary>
        /// Creates a new rate limiter object
        /// </summary>
        /// <param name="server_static_public"></param>
        /// <param name="limit"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private unsafe void NewRateLimiter(string server_static_public, UInt64 limit)
        {
            // Create a new tunnel:
            object?* newRL = new_rate_limiter(server_static_public, limit);
            // Ensure tunnel is not null:
            if (newRL == null)
            {
                throw new InvalidOperationException("Failed to create new rate limiter");
            }
            rateLimiter = (object*)newRL;
        }

        #region BoringTun Functions
        /// <summary>
        /// Create a new Rate Limit object
        /// </summary>
        /// <param name="server_static_public"></param>
        /// <param name="limit"></param>
        /// <returns></returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern object?* new_rate_limiter(string server_static_public, UInt64 limit);

        /// <summary>
        /// Disposes of the rate limiter object
        /// </summary>
        /// <param name="rateLimiter"></param>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern void rate_limiter_free(object* rateLimiter);

        /// <summary>
        /// Verify a packet with the rate limiter
        /// </summary>
        /// <param name="rateLimiter"></param>
        /// <param name="src"></param>
        /// <param name="src_size"></param>
        /// <param name="dst"></param>
        /// <param name="dst_size"></param>
        /// <returns>A wireguard verify result</returns>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern WireguardVerifyResult wireguard_verify_packet(object* rateLimiter, byte[] src, uint src_size, byte[] dst, uint dst_size);

        /// <summary>
        /// Reset the rate limiter count
        /// Reccomended to call ~1 time per second
        /// </summary>
        /// <param name="rateLimiter"></param>
        [DllImport(BoringTunDLLLocation.DLLName, CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern void wireguard_reset_count(object* rateLimiter);

        #endregion
        #region BoringTun Structs
        struct WireguardVerifyResult
        {
            public wireguard_result result;
            public int idx; // idx (-1 if not available)
        };
        #endregion
    }
}

