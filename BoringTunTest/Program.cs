using BoringTunSharp;
using BoringTunTest;

// Set logger:
LoggingTest testLog = new LoggingTest();
BoringTunLogger.SetLogging(testLog.logDelegateTest);

// Generate a key pair:
X25519KeyPair key = new X25519KeyPair();
Console.WriteLine("Private: "+key.PrivateKeyBase64()+" public: "+key.PublicKeyBase64());