using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Tests
{
    [TestClass]
    public class LoggerTests
    {
        private string _testLogsPath;
        
        [TestInitialize]
        public void TestInitialize()
        {
            // Create a test logs directory
            _testLogsPath = Path.Combine(Path.GetTempPath(), "WinSecMonitorTests", "Logs");
            
            if (Directory.Exists(_testLogsPath))
            {
                Directory.Delete(_testLogsPath, true);
            }
            
            Directory.CreateDirectory(_testLogsPath);
            
            // Set the log file path using reflection
            var logFilePathField = typeof(Logger).GetField("_logFilePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var debugLogFilePathField = typeof(Logger).GetField("_debugLogFilePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            if (logFilePathField != null && debugLogFilePathField != null)
            {
                logFilePathField.SetValue(Logger.Instance, Path.Combine(_testLogsPath, "application.log"));
                debugLogFilePathField.SetValue(Logger.Instance, Path.Combine(_testLogsPath, "debug.log"));
            }
            
            // Reset debug mode
            Logger.Instance.DebugModeEnabled = false;
            
            // Flush any existing logs
            var flushMethod = typeof(Logger).GetMethod("FlushLogBuffer", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            if (flushMethod != null)
            {
                flushMethod.Invoke(Logger.Instance, null);
            }
        }
        
        [TestCleanup]
        public void TestCleanup()
        {
            // Clean up test logs directory
            if (Directory.Exists(_testLogsPath))
            {
                try
                {
                    Directory.Delete(_testLogsPath, true);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }
        
        [TestMethod]
        public void Logger_LogsMessage_WithCorrectLevel()
        {
            // Arrange
            string testMessage = "Test log message";
            
            // Act
            Logger.Instance.LogInformation(testMessage);
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "[Information]");
            StringAssert.Contains(logContent, testMessage);
        }
        
        [TestMethod]
        public void Logger_DebugMode_LogsDebugMessages()
        {
            // Arrange
            string testMessage = "Test debug message";
            Logger.Instance.DebugModeEnabled = true;
            
            // Act
            Logger.Instance.LogDebug(testMessage);
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "debug.log"));
            StringAssert.Contains(logContent, "[Debug]");
            StringAssert.Contains(logContent, testMessage);
        }
        
        [TestMethod]
        public void Logger_NoDebugMode_SkipsDebugMessages()
        {
            // Arrange
            string testMessage = "Test debug message";
            Logger.Instance.DebugModeEnabled = false;
            
            // Act
            Logger.Instance.LogDebug(testMessage);
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            string debugLogPath = Path.Combine(_testLogsPath, "debug.log");
            Assert.IsFalse(File.Exists(debugLogPath), "Debug log file should not exist when debug mode is disabled");
            
            string appLogPath = Path.Combine(_testLogsPath, "application.log");
            if (File.Exists(appLogPath))
            {
                string logContent = File.ReadAllText(appLogPath);
                Assert.IsFalse(logContent.Contains(testMessage), "Debug message should not be logged when debug mode is disabled");
            }
        }
        
        [TestMethod]
        public async Task Logger_LogsMessageAsync_WithCorrectLevel()
        {
            // Arrange
            string testMessage = "Test async log message";
            
            // Act
            await Logger.Instance.LogInformationAsync(testMessage);
            
            // Assert
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "[Information]");
            StringAssert.Contains(logContent, testMessage);
        }
        
        [TestMethod]
        public void Logger_LogsException_WithStackTrace()
        {
            // Arrange
            Exception testException = null;
            try
            {
                throw new InvalidOperationException("Test exception");
            }
            catch (Exception ex)
            {
                testException = ex;
            }
            
            // Act
            Logger.Instance.LogException(testException);
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "[Error]");
            StringAssert.Contains(logContent, "Test exception");
            StringAssert.Contains(logContent, "Stack trace:");
        }
    }
}