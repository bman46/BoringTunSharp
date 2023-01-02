namespace BoringTunTest
{
	public class LoggingTest
	{
		/// <summary>
		/// Basic logging method. Tests using dynamic functions and avoiding GC.
		/// </summary>
		/// <param name="msg"></param>
		public void logDelegateTest(string msg)
		{
			Console.WriteLine(msg);
		}
	}
}

