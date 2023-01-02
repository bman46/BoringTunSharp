using BoringTunSharp;
using BoringTunTest;

// Set logger:
LoggingTest testLog = new LoggingTest();
BoringTunLogger.SetLogging(testLog.logDelegateTest);

try
{
    // This should fail
    BoringTunLogger.SetLogging(testLog.logDelegateTest);
}
catch (InvalidOperationException e)
{
    Console.WriteLine("Correctly failed to set logging twice. Error: "+e.Message);
}

// Generate key pairs:
X25519KeyPair clientKey = new X25519KeyPair();
X25519KeyPair serverKey = new X25519KeyPair();
Console.WriteLine("Private: "+clientKey.PrivateKeyBase64()+" public: "+clientKey.PublicKeyBase64());
Console.WriteLine("Private: " + serverKey.PrivateKeyBase64() + " public: " + serverKey.PublicKeyBase64());

string sharedKey = X25519KeyPair.KeyToBase64(X25519KeyPair.GenerateSecretKey());


// Create a mock tunnel within this process
using (WireGuardTunnel client = new WireGuardTunnel(clientKey.PrivateKeyBase64(), serverKey.PublicKeyBase64(), sharedKey, 100, 0))
{
    using (WireGuardTunnel server = new WireGuardTunnel(serverKey.PrivateKeyBase64(), clientKey.PublicKeyBase64(), sharedKey, 10, 0))
    {
        // Start a handshake:
        var handshake = client.Handshake();
        bool toServer = true;
        Console.WriteLine("Handshake: "+handshake?.SendTo);
        while (handshake != null)
        {
            if (toServer)
            {
                Console.WriteLine("Send to server");
                handshake = server.Decapsulate(handshake.Data);
                Console.WriteLine("Result: " + handshake?.SendTo);
                toServer = !toServer;
            }
            else
            {
                Console.WriteLine("Send to client");
                handshake = client.Decapsulate(handshake.Data);
                Console.WriteLine("Result: "+handshake?.SendTo);
                toServer = !toServer;
            }
        }
        Console.WriteLine("Handshake complete!");
    }
}
Console.WriteLine("Done!");