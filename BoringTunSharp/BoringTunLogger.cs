using System;
using System.Runtime.InteropServices;

namespace BoringTunSharp
{
	public class BoringTunLogger
	{
        /// <summary>
        /// Set the function to use for logging.
        /// </summary>
        /// <param name="logDel"></param>
        public static void SetLogging(LoggingCallbackDelegate logDel)
        {
            // Set to a static var to guard against GC.
            loggingDelegateInstance = logDel;
            bool result = set_logging_function(logDel);
            // Ensure it was successful:
            if (!result)
            {
                throw new ArgumentException("Failed to set boringtun logging function.");
            }
        }

        /// <summary>
        /// Internal copy of the logging delegate to prevent GC removal.
        /// </summary>
        private static LoggingCallbackDelegate? loggingDelegateInstance;

        /// <summary>
        /// Callback delegate for BoringTun Logging
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void LoggingCallbackDelegate(string msg);

        /// <summary>
        /// Set the logging delegate.
        /// </summary>
        /// <remarks>
        /// SAFETY:
        /// `c_char` will be freed by the library after calling `log_func`. If the value needs to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
        /// </remarks>
        /// <param name="loggingDelegate">The delegate to use for logging</param>
        /// <returns>false on failure</returns>
        [DllImport("libboringtun", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool set_logging_function(LoggingCallbackDelegate loggingDelegate);

    }
}

