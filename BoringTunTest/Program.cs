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
X25519KeyPair client = new X25519KeyPair();
X25519KeyPair server = new X25519KeyPair();
Console.WriteLine("Private: "+client.PrivateKeyBase64()+" public: "+client.PublicKeyBase64());
Console.WriteLine("Private: " + server.PrivateKeyBase64() + " public: " + server.PublicKeyBase64());

string sharedKey = X25519KeyPair.KeyToBase64(X25519KeyPair.GenerateSecretKey());


// Create a tunnel
WireGuardTunnel tun = new WireGuardTunnel(client.PrivateKeyBase64(), server.PublicKeyBase64(), sharedKey, 10, 0);
tun.Dispose();

Console.WriteLine("Done!");