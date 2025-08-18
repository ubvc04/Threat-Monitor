using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Utils.ErrorHandling
{
    public static class ExceptionHandler
    {
        public static void Initialize(Application app)
        {
            // Handle exceptions in the UI thread
            app.DispatcherUnhandledException += OnDispatcherUnhandledException;
            
            // Handle exceptions in background threads
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
            
            // Handle exceptions that weren't caught by the above
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            
            Logger.Instance.LogInformation("Global exception handling initialized");
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            try
            {
                Logger.Instance.LogException(e.Exception, "Unhandled exception in UI thread");
                
                MessageBox.Show(
                    $"An unexpected error occurred. The application may be in an unstable state.\n\nError: {e.Exception.Message}", 
                    "Application Error", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
                
                // Mark as handled to prevent application crash
                e.Handled = true;
            }
            catch (Exception ex)
            {
                // Last resort if even our error handling fails
                MessageBox.Show(
                    $"Critical error in exception handler: {ex.Message}", 
                    "Critical Error", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
            }
        }

        private static void OnUnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            try
            {
                Logger.Instance.LogException(e.Exception, "Unobserved task exception");
                
                // Mark as observed to prevent application crash
                e.SetObserved();
            }
            catch (Exception ex)
            {
                // Last resort if even our error handling fails
                MessageBox.Show(
                    $"Critical error in exception handler: {ex.Message}", 
                    "Critical Error", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
            }
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                if (e.ExceptionObject is Exception exception)
                {
                    Logger.Instance.LogException(exception, "Unhandled domain exception");
                }
                else
                {
                    Logger.Instance.LogCritical($"Unhandled non-exception object: {e.ExceptionObject}");
                }

                MessageBox.Show(
                    "A critical error has occurred and the application needs to close.", 
                    "Critical Error", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
            }
            catch
            {
                // At this point, we can't do much more
            }
            finally
            {
                if (e.IsTerminating)
                {
                    // Perform any cleanup if needed before termination
                }
            }
        }
    }
}