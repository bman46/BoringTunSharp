using System;
using BoringTunSharp;
using BoringTunSharp.Crypto;
using BoringTunSharp.Tunneling.RateLimiter;

namespace BoringTunTest
{
    public class SingleSession
    {
        public static void TestSingleSession()
        {
            // Generate key pairs:
            X25519KeyPair clientKey = new X25519KeyPair();
            X25519KeyPair serverKey = new X25519KeyPair();
            IX25519Key sharedKey = new X25519PrivateKey();
            Console.WriteLine("Client: Private: " + clientKey.PrivateKey.Base64() + " public: " + clientKey.PublicKey.Base64());
            Console.WriteLine("Server: Private: " + serverKey.PrivateKey.Base64() + " public: " + serverKey.PublicKey.Base64());
            Console.WriteLine("Shared Key: " + sharedKey.Base64());

            // Create Rate Limiter for server
            RateLimiter serverRateLimiter = new RateLimiter(serverKey, 100);

            // Create a mock tunnel within this process
            using (WireGuardTunnel client = new WireGuardTunnel(clientKey, serverKey.PublicKey, sharedKey, 100, 1))
            {
                using (WireGuardTunnel server = new WireGuardTunnel(serverKey, clientKey.PublicKey, sharedKey, 100, 5))
                {
                    // Start a handshake:
                    var handshake = client.Handshake();
                    Console.WriteLine("Handshake: " + handshake?.SendTo);
                    bool toServer = true;
                    while (handshake != null)
                    {
                        if (toServer)
                        {
                            Console.WriteLine("Send to server");
                            var result = serverRateLimiter.ProcessPacket(handshake.Data);
                            Console.WriteLine(result);
                            handshake = server.Decapsulate(handshake.Data);
                            Console.WriteLine("Result: " + handshake?.SendTo);
                            toServer = !toServer;
                        }
                        else
                        {
                            Console.WriteLine("Send to client");
                            handshake = client.Decapsulate(handshake.Data);
                            Console.WriteLine("Result: " + handshake?.SendTo);
                            toServer = !toServer;
                        }
                    }
                    Console.WriteLine("Handshake complete!");

                    // Example TCP/IP SYN packet:
                    string ip_header = "45000028";  // Version, IHL, Type of Service | Total Length
                    ip_header += "abcd0000"; // Identification | Flags, Fragment Offset
                    ip_header += "4006a6ec"; // TTL, Protocol | Header Checksum
                    ip_header += "0a0a0a02"; // Source Address
                    ip_header += "0a0a0a01"; // Destination Address

                    string tcp_header = "30390050"; // Source Port | Destination Port
                    tcp_header += "00000000"; // Sequence Number
                    tcp_header += "00000000"; // Acknowledgement Number
                    tcp_header += "50027110"; // Data Offset, Reserved, Flags | Window Size
                    tcp_header += "e6320000"; // Checksum | Urgent Pointer

                    byte[] packet = Convert.FromHexString(ip_header + tcp_header);
                    Console.WriteLine("Client Input: " + Convert.ToBase64String(packet));

                    var encryptedData = client.Encapsulate(packet);

                    Console.WriteLine("Encrypted Data: " + Convert.ToBase64String(encryptedData?.Data));
                    toServer = true;
                    // This should only run once:
                    while (encryptedData != null && encryptedData.SendTo != WireGuardData.Destination.Tunnel_IPv4)
                    {
                        if (toServer)
                        {
                            Console.WriteLine("Send to server");
                            var result = serverRateLimiter.ProcessPacket(encryptedData.Data);
                            Console.WriteLine(result);
                            encryptedData = server.Decapsulate(encryptedData.Data);
                            Console.WriteLine("Result: " + encryptedData?.SendTo);
                            toServer = !toServer;
                        }
                        else
                        {
                            Console.WriteLine("Send to client");
                            encryptedData = client.Decapsulate(encryptedData.Data);
                            Console.WriteLine("Result: " + encryptedData?.SendTo);
                            toServer = !toServer;
                        }
                    }
                    Console.WriteLine("Server Result: " + Convert.ToBase64String(encryptedData?.Data));
                    if (packet.SequenceEqual(encryptedData?.Data))
                    {
                        Console.WriteLine("The data from the client is the same as the data arrived at the server!");
                    }
                    else
                    {
                        throw new Exception("Decrypted packet different from original.");
                    }
                    Console.WriteLine("Done packet transmission");
                    Console.WriteLine("Client Stats:");
                    Console.WriteLine(client.GetTunnelStats());
                    Console.WriteLine("Server Stats:");
                    Console.WriteLine(server.GetTunnelStats());
                }
            }
        }
    }
}

