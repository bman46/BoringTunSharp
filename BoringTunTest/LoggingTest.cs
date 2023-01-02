namespace BoringTunTest
{
    public class LoggingTest
    {
        /// <summary>
        /// Basic logging method. Tests using dynamic functions and avoiding GC.
        /// </summary>
        /// <param name="msg">The MSG from wireguard</param>
        public void logDelegateTest(string msg)
        {
            // Write the msg
            Console.WriteLine(msg);
        }
    }
}

