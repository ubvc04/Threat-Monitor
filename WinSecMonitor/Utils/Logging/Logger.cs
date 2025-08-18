using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq;

namespace WinSecMonitor.Utils.Logging
{
    public enum LogLevel
    {
        Debug,
        Information,
        Warning,
        Error,
        Critical
    }

    public class Logger
    {
        private static readonly Lazy<Logger> _instance = new Lazy<Logger>(() => new Logger());
        private readonly string _logFilePath;
        private readonly string _debugLogFilePath;
        private readonly object _lockObject = new object();
        
        private bool _debugModeEnabled = false;
        private int _maxLogFileSizeBytes = 10 * 1024 * 1024; // 10 MB default
        private int _maxLogFiles = 5;
        private List<string> _logBuffer = new List<string>();
        private int _bufferSize = 100; // Number of log entries to buffer before writing to file

        public static Logger Instance => _instance.Value;

        private Logger()
        {
            string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSecMonitor");
            string logsPath = Path.Combine(appDataPath, "Logs");
            
            if (!Directory.Exists(logsPath))
            {
                Directory.CreateDirectory(logsPath);
            }

            _logFilePath = Path.Combine(logsPath, "application.log");
            _debugLogFilePath = Path.Combine(logsPath, "debug.log");
            
            // Clean up old log files on startup
            CleanupOldLogFiles(logsPath);
        }
        
        /// <summary>
        /// Gets or sets whether debug mode is enabled
        /// </summary>
        public bool DebugModeEnabled
        {
            get => _debugModeEnabled;
            set
            {
                _debugModeEnabled = value;
                LogInformation($"Debug mode {(_debugModeEnabled ? "enabled" : "disabled")}");
            }
        }
        
        /// <summary>
        /// Gets or sets the maximum log file size in bytes
        /// </summary>
        public int MaxLogFileSizeBytes
        {
            get => _maxLogFileSizeBytes;
            set => _maxLogFileSizeBytes = Math.Max(1024 * 1024, value); // Minimum 1 MB
        }
        
        /// <summary>
        /// Gets or sets the maximum number of log files to keep
        /// </summary>
        public int MaxLogFiles
        {
            get => _maxLogFiles;
            set => _maxLogFiles = Math.Max(1, value); // Minimum 1 file
        }

        public void Log(LogLevel level, string message)
        {
            // Skip debug messages if debug mode is not enabled
            if (level == LogLevel.Debug && !_debugModeEnabled)
                return;
                
            string formattedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
            
            // Add to buffer
            lock (_lockObject)
            {
                _logBuffer.Add(formattedMessage);
                
                // Write to file if buffer is full or for higher priority messages
                if (_logBuffer.Count >= _bufferSize || level >= LogLevel.Warning)
                {
                    FlushLogBuffer();
                }
            }

            // Also output to console for debugging purposes
            if (_debugModeEnabled || Debugger.IsAttached)
            {
                Console.WriteLine(formattedMessage);
            }
        }
        
        /// <summary>
        /// Flushes the log buffer to the log file
        /// </summary>
        public void FlushLogBuffer()
        {
            lock (_lockObject)
            {
                if (_logBuffer.Count == 0)
                    return;
                    
                try
                {
                    // Check if log file needs rotation
                    CheckLogFileSize();
                    
                    // Write all buffered messages
                    File.AppendAllLines(_logFilePath, _logBuffer);
                    
                    // Write debug messages to debug log file if debug mode is enabled
                    if (_debugModeEnabled)
                    {
                        File.AppendAllLines(_debugLogFilePath, _logBuffer);
                    }
                    
                    // Clear the buffer
                    _logBuffer.Clear();
                }
                catch (Exception ex)
                {
                    // If we can't write to the log file, output to console
                    Console.WriteLine($"Error writing to log file: {ex.Message}");
                    Console.WriteLine(string.Join(Environment.NewLine, _logBuffer));
                    _logBuffer.Clear();
                }
            }
        }

        public void LogDebug(string message) => Log(LogLevel.Debug, message);
        public void LogInformation(string message) => Log(LogLevel.Information, message);
        public void LogWarning(string message) => Log(LogLevel.Warning, message);
        public void LogError(string message) => Log(LogLevel.Error, message);
        public void LogCritical(string message) => Log(LogLevel.Critical, message);

        public void LogException(Exception ex, string context = null)
        {
            string message = string.IsNullOrEmpty(context) 
                ? $"Exception: {ex.Message}\nStackTrace: {ex.StackTrace}"
                : $"Context: {context}\nException: {ex.Message}\nStackTrace: {ex.StackTrace}";

            Log(LogLevel.Error, message);

            if (ex.InnerException != null)
            {
                Log(LogLevel.Error, $"Inner Exception: {ex.InnerException.Message}\nStackTrace: {ex.InnerException.StackTrace}");
            }
        }

        public async Task LogAsync(LogLevel level, string message)
        {
            // Skip debug messages if debug mode is not enabled
            if (level == LogLevel.Debug && !_debugModeEnabled)
                return;
                
            string formattedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
            
            try
            {
                // Check if log file needs rotation
                CheckLogFileSize();
                
                // Write to log file
                await File.AppendAllTextAsync(_logFilePath, formattedMessage + Environment.NewLine);
                
                // Write to debug log file if debug mode is enabled
                if (_debugModeEnabled)
                {
                    await File.AppendAllTextAsync(_debugLogFilePath, formattedMessage + Environment.NewLine);
                }
                
                // Also output to console for debugging purposes
                if (_debugModeEnabled || Debugger.IsAttached)
                {
                    Console.WriteLine(formattedMessage);
                }
            }
            catch (Exception ex)
            {
                // If we can't write to the log file, output to console
                Console.WriteLine($"Error writing to log file: {ex.Message}");
                Console.WriteLine(formattedMessage);
            }
        }
        
        /// <summary>
        /// Checks if the log file size exceeds the maximum size and rotates it if necessary
        /// </summary>
        private void CheckLogFileSize()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    FileInfo fileInfo = new FileInfo(_logFilePath);
                    if (fileInfo.Length > _maxLogFileSizeBytes)
                    {
                        RotateLogFiles();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking log file size: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Rotates log files by renaming the current log file and creating a new one
        /// </summary>
        private void RotateLogFiles()
        {
            try
            {
                string directory = Path.GetDirectoryName(_logFilePath);
                string fileName = Path.GetFileNameWithoutExtension(_logFilePath);
                string extension = Path.GetExtension(_logFilePath);
                
                // Shift existing log files
                for (int i = _maxLogFiles - 1; i >= 1; i--)
                {
                    string sourceFile = Path.Combine(directory, $"{fileName}.{i}{extension}");
                    string destFile = Path.Combine(directory, $"{fileName}.{i + 1}{extension}");
                    
                    if (File.Exists(destFile))
                        File.Delete(destFile);
                        
                    if (File.Exists(sourceFile))
                        File.Move(sourceFile, destFile);
                }
                
                // Rename current log file
                string newFile = Path.Combine(directory, $"{fileName}.1{extension}");
                if (File.Exists(newFile))
                    File.Delete(newFile);
                    
                File.Move(_logFilePath, newFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error rotating log files: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Cleans up old log files, keeping only the maximum number of files
        /// </summary>
        private void CleanupOldLogFiles(string logsDirectory)
        {
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(logsDirectory);
                FileInfo[] logFiles = dirInfo.GetFiles("*.log").OrderByDescending(f => f.LastWriteTime).ToArray();
                
                // Keep the most recent MaxLogFiles files
                for (int i = _maxLogFiles; i < logFiles.Length; i++)
                {
                    try
                    {
                        logFiles[i].Delete();
                    }
                    catch
                    {
                        // Ignore errors when deleting old log files
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error cleaning up old log files: {ex.Message}");
            }
        }
    }
}