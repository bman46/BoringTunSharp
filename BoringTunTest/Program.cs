using BoringTunSharp;
using BoringTunSharp.Crypto;
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
Console.WriteLine("Done!");

// Test single session:
SingleSession.TestSingleSession();

// Test Multi session (server):
// TODO
