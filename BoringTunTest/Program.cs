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

// Generate a key pair:
X25519KeyPair key = new X25519KeyPair();
Console.WriteLine("Private: "+key.PrivateKeyBase64()+" public: "+key.PublicKeyBase64());