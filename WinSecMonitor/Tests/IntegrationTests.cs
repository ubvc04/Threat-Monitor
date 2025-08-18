using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Tests
{
    [TestClass]
    public class IntegrationTests
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
            Logger.Instance.FlushLogBuffer();
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
        public void GuiExceptionHandler_LogsException_WhenHandlingException()
        {
            // Arrange
            var testException = new InvalidOperationException("Test integration exception");
            var handler = new GuiExceptionHandler();
            
            // Act - Process exception through the handler
            handler.ProcessException(testException, "Test Operation");
            Logger.Instance.FlushLogBuffer();
            
            // Assert - Verify the exception was logged
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "[Error]");
            StringAssert.Contains(logContent, "Test integration exception");
            StringAssert.Contains(logContent, "Test Operation");
        }
        
        [TestMethod]
        public void GuiExceptionHandler_SafeExecute_HandlesExceptions()
        {
            // Arrange
            bool exceptionHandled = false;
            var handler = new GuiExceptionHandler();
            
            // Act - Execute an action that throws an exception
            bool result = handler.SafeExecute(() => {
                throw new InvalidOperationException("Test safe execute exception");
            }, "Safe Execute Test", () => {
                exceptionHandled = true;
            });
            
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            Assert.IsFalse(result, "SafeExecute should return false when an exception occurs");
            Assert.IsTrue(exceptionHandled, "The onError callback should have been executed");
            
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "Test safe execute exception");
            StringAssert.Contains(logContent, "Safe Execute Test");
        }
        
        [TestMethod]
        public void GuiExceptionHandler_SafeExecuteFunction_ReturnsDefaultOnException()
        {
            // Arrange
            var handler = new GuiExceptionHandler();
            
            // Act - Execute a function that throws an exception
            string result = handler.SafeExecuteFunction<string>(() => {
                throw new InvalidOperationException("Test safe execute function exception");
                return "Success";
            }, "Safe Execute Function Test", defaultValue: "Default");
            
            Logger.Instance.FlushLogBuffer();
            
            // Assert
            Assert.AreEqual("Default", result, "SafeExecuteFunction should return the default value when an exception occurs");
            
            string logContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            StringAssert.Contains(logContent, "Test safe execute function exception");
            StringAssert.Contains(logContent, "Safe Execute Function Test");
        }
        
        [TestMethod]
        public async Task Logger_And_GuiExceptionHandler_WorkTogether_Async()
        {
            // Arrange
            var handler = new GuiExceptionHandler();
            Logger.Instance.DebugModeEnabled = true;
            
            // Act - Log some messages and handle an exception
            await Logger.Instance.LogDebugAsync("Debug test message");
            await Logger.Instance.LogInformationAsync("Info test message");
            
            await Task.Run(() => {
                handler.ProcessException(
                    new InvalidOperationException("Async test exception"),
                    "Async Test Operation");
            });
            
            // Assert
            string appLogContent = File.ReadAllText(Path.Combine(_testLogsPath, "application.log"));
            string debugLogContent = File.ReadAllText(Path.Combine(_testLogsPath, "debug.log"));
            
            // Verify debug message in debug log
            StringAssert.Contains(debugLogContent, "Debug test message");
            
            // Verify info message in both logs
            StringAssert.Contains(appLogContent, "Info test message");
            StringAssert.Contains(debugLogContent, "Info test message");
            
            // Verify exception in both logs
            StringAssert.Contains(appLogContent, "Async test exception");
            StringAssert.Contains(debugLogContent, "Async test exception");
            StringAssert.Contains(appLogContent, "Async Test Operation");
        }
    }
}