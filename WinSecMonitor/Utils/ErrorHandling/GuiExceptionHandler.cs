using System;
using System.Windows;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Utils.ErrorHandling
{
    /// <summary>
    /// Handles exceptions specific to GUI components with user-friendly messages
    /// </summary>
    public static class GuiExceptionHandler
    {
        private static readonly Logger _logger = Logger.Instance;

        /// <summary>
        /// Initializes the GUI exception handler
        /// </summary>
        public static void Initialize()
        {
            // Handle exceptions in the UI thread
            Application.Current.DispatcherUnhandledException += OnDispatcherUnhandledException;
        }

        /// <summary>
        /// Handles unhandled exceptions in the UI thread
        /// </summary>
        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            HandleException(e.Exception);
            e.Handled = true; // Mark as handled to prevent application crash
        }

        /// <summary>
        /// Handles exceptions with appropriate logging and user feedback
        /// </summary>
        public static void HandleException(Exception ex, string context = null)
        {
            string message = context != null ? $"{context}: {ex.Message}" : ex.Message;
            _logger.LogException(message, ex);

            // Show user-friendly message based on exception type
            string userMessage = GetUserFriendlyMessage(ex, context);
            MessageBoxImage icon = GetMessageBoxIcon(ex);

            // Show message on UI thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show(userMessage, "Application Error", MessageBoxButton.OK, icon);
            });
        }

        /// <summary>
        /// Executes an action with exception handling
        /// </summary>
        public static void ExecuteSafe(Action action, string context = null)
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                HandleException(ex, context);
            }
        }

        /// <summary>
        /// Executes a function with exception handling and returns a default value if an exception occurs
        /// </summary>
        public static T ExecuteSafe<T>(Func<T> func, T defaultValue = default, string context = null)
        {
            try
            {
                return func();
            }
            catch (Exception ex)
            {
                HandleException(ex, context);
                return defaultValue;
            }
        }

        /// <summary>
        /// Gets a user-friendly message based on the exception type
        /// </summary>
        private static string GetUserFriendlyMessage(Exception ex, string context)
        {
            string baseMessage = context != null ? $"An error occurred while {context}." : "An error occurred.";

            if (ex is NullReferenceException)
            {
                return $"{baseMessage} The application encountered a null reference. This might be due to missing data.";
            }
            else if (ex is InvalidOperationException)
            {
                return $"{baseMessage} The requested operation cannot be completed at this time.";
            }
            else if (ex is ArgumentException)
            {
                return $"{baseMessage} Invalid input or argument provided.";
            }
            else if (ex is System.IO.IOException)
            {
                return $"{baseMessage} A file or I/O error occurred. Please check file permissions and disk space.";
            }
            else if (ex is System.Net.WebException)
            {
                return $"{baseMessage} A network error occurred. Please check your internet connection.";
            }
            else if (ex is System.Data.DataException)
            {
                return $"{baseMessage} A data error occurred. The data may be corrupted or in an unexpected format.";
            }
            else if (ex is System.ComponentModel.DataAnnotations.ValidationException)
            {
                return $"{baseMessage} The data validation failed. Please check your input.";
            }
            else if (ex is System.Windows.Markup.XamlParseException)
            {
                return $"{baseMessage} A UI rendering error occurred. Please restart the application.";
            }
            else
            {
                // For unknown exceptions, provide a generic message with the actual error for troubleshooting
                return $"{baseMessage} Details: {ex.Message}";
            }
        }

        /// <summary>
        /// Gets the appropriate message box icon based on the exception type
        /// </summary>
        private static MessageBoxImage GetMessageBoxIcon(Exception ex)
        {
            if (ex is System.IO.IOException || ex is System.Net.WebException)
            {
                return MessageBoxImage.Warning;
            }
            else if (ex is OutOfMemoryException || ex is StackOverflowException)
            {
                return MessageBoxImage.Error;
            }
            else
            {
                return MessageBoxImage.Information;
            }
        }
    }
}