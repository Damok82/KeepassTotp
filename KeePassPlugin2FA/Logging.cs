using System;
using System.IO;

namespace KeePassPlugin2FA
{
    public static class Logging
    {
        private const string RelativeLogFilePath = "KeePassPlugin2FA\\log.txt";

        private static readonly string _logFilePath = Path.Combine(Path.GetTempPath(), RelativeLogFilePath);

        public static bool IsActivated;

        public static void LogMessage(string message)
        {
#if DEBUG
            IsActivated = true;
#endif
            if (!IsActivated)
            {
                return;
            }

            if (string.IsNullOrEmpty(message?.Trim()))
            {
                message = string.Empty;
            }

            string logFileDirectoryPath = Path.GetDirectoryName(_logFilePath);
            if (!Directory.Exists(logFileDirectoryPath))
            {
                // ReSharper disable once AssignNullToNotNullAttribute
                DirectoryInfo directoryInfo = Directory.CreateDirectory(logFileDirectoryPath);
                if (!directoryInfo.Exists)
                {
                    throw new Exception($"Could not create log file directory ({logFileDirectoryPath})");
                }
            }

            string logMessage = $"[{DateTime.Now}] {message}\r\n";
            File.AppendAllText(_logFilePath, logMessage);
        }
    }
}
