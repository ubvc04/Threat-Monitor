using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Timers;
using System.Windows;

namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Manages and coordinates file and registry monitoring components
    /// </summary>
    public class FileRegistryMonitoringManager : INotifyPropertyChanged, IDisposable
    {
        #region Private Fields

        private readonly FileMonitor _fileMonitor;
        private readonly RegistryMonitor _registryMonitor;
        private readonly FileRegistryConfiguration _configuration;
        private readonly Timer _refreshTimer;
        private bool _isInitialized;
        private bool _isDisposed;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the file monitor instance
        /// </summary>
        public FileMonitor FileMonitor => _fileMonitor;

        /// <summary>
        /// Gets the registry monitor instance
        /// </summary>
        public RegistryMonitor RegistryMonitor => _registryMonitor;

        /// <summary>
        /// Gets the configuration instance
        /// </summary>
        public FileRegistryConfiguration Configuration => _configuration;

        private bool _isMonitoring;
        /// <summary>
        /// Gets or sets whether monitoring is active
        /// </summary>
        public bool IsMonitoring
        {
            get { return _isMonitoring; }
            private set
            {
                if (_isMonitoring != value)
                {
                    _isMonitoring = value;
                    OnPropertyChanged(nameof(IsMonitoring));
                }
            }
        }

        private int _totalFileChanges;
        /// <summary>
        /// Gets the total number of file changes detected
        /// </summary>
        public int TotalFileChanges
        {
            get { return _totalFileChanges; }
            private set
            {
                if (_totalFileChanges != value)
                {
                    _totalFileChanges = value;
                    OnPropertyChanged(nameof(TotalFileChanges));
                }
            }
        }

        private int _totalRegistryChanges;
        /// <summary>
        /// Gets the total number of registry changes detected
        /// </summary>
        public int TotalRegistryChanges
        {
            get { return _totalRegistryChanges; }
            private set
            {
                if (_totalRegistryChanges != value)
                {
                    _totalRegistryChanges = value;
                    OnPropertyChanged(nameof(TotalRegistryChanges));
                }
            }
        }

        private int _highSeverityChanges;
        /// <summary>
        /// Gets the number of high severity changes detected
        /// </summary>
        public int HighSeverityChanges
        {
            get { return _highSeverityChanges; }
            private set
            {
                if (_highSeverityChanges != value)
                {
                    _highSeverityChanges = value;
                    OnPropertyChanged(nameof(HighSeverityChanges));
                }
            }
        }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the FileRegistryMonitoringManager class
        /// </summary>
        public FileRegistryMonitoringManager()
        {
            try
            {
                // Create configuration
                _configuration = new FileRegistryConfiguration();

                // Create monitors
                _fileMonitor = new FileMonitor();
                _registryMonitor = new RegistryMonitor();

                // Create refresh timer
                _refreshTimer = new Timer();
                _refreshTimer.Elapsed += OnRefreshTimerElapsed;

                // Initialize
                Initialize();
            }
            catch (Exception ex)
            {
                LogError($"Error initializing FileRegistryMonitoringManager: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring file and registry changes
        /// </summary>
        public void StartMonitoring()
        {
            try
            {
                if (!_isInitialized)
                {
                    Initialize();
                }

                if (IsMonitoring)
                {
                    LogWarning("Monitoring is already active");
                    return;
                }

                // Start file monitoring if enabled
                if (_configuration.EnableFileMonitoring)
                {
                    _fileMonitor.StartMonitoring();
                    LogInfo("File monitoring started");
                }

                // Start registry monitoring if enabled
                if (_configuration.EnableRegistryMonitoring)
                {
                    _registryMonitor.StartMonitoring();
                    LogInfo("Registry monitoring started");
                }

                // Start refresh timer
                _refreshTimer.Interval = _configuration.RefreshIntervalSeconds * 1000;
                _refreshTimer.Start();

                IsMonitoring = true;
                LogInfo("Monitoring started");
            }
            catch (Exception ex)
            {
                LogError($"Error starting monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stops monitoring file and registry changes
        /// </summary>
        public void StopMonitoring()
        {
            try
            {
                if (!IsMonitoring)
                {
                    LogWarning("Monitoring is not active");
                    return;
                }

                // Stop file monitoring
                _fileMonitor.StopMonitoring();

                // Stop registry monitoring
                _registryMonitor.StopMonitoring();

                // Stop refresh timer
                _refreshTimer.Stop();

                IsMonitoring = false;
                LogInfo("Monitoring stopped");
            }
            catch (Exception ex)
            {
                LogError($"Error stopping monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Refreshes monitoring data
        /// </summary>
        public void RefreshData()
        {
            try
            {
                // Refresh registry data (file changes are event-driven)
                if (_configuration.EnableRegistryMonitoring && IsMonitoring)
                {
                    _registryMonitor.RefreshChanges();
                }

                // Update statistics
                UpdateStatistics();

                LogInfo("Monitoring data refreshed");
            }
            catch (Exception ex)
            {
                LogError($"Error refreshing monitoring data: {ex.Message}");
            }
        }

        /// <summary>
        /// Clears all detected changes
        /// </summary>
        public void ClearAllChanges()
        {
            try
            {
                _fileMonitor.ClearChanges();
                _registryMonitor.ClearChanges();
                UpdateStatistics();
                LogInfo("All changes cleared");
            }
            catch (Exception ex)
            {
                LogError($"Error clearing changes: {ex.Message}");
            }
        }

        /// <summary>
        /// Exports all changes to CSV files
        /// </summary>
        /// <param name="directoryPath">Directory to save the CSV files</param>
        /// <returns>True if export was successful, false otherwise</returns>
        public bool ExportChangesToCsv(string directoryPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(directoryPath))
                {
                    LogWarning("Export directory path is empty");
                    return false;
                }

                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string fileChangesPath = Path.Combine(directoryPath, $"FileChanges_{timestamp}.csv");
                string registryChangesPath = Path.Combine(directoryPath, $"RegistryChanges_{timestamp}.csv");

                bool fileExportSuccess = _fileMonitor.ExportChangesToCsv(fileChangesPath);
                bool registryExportSuccess = _registryMonitor.ExportChangesToCsv(registryChangesPath);

                LogInfo($"Changes exported to {directoryPath}");
                return fileExportSuccess && registryExportSuccess;
            }
            catch (Exception ex)
            {
                LogError($"Error exporting changes to CSV: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Saves the current configuration to a file
        /// </summary>
        /// <param name="filePath">Path to save the configuration file</param>
        public void SaveConfiguration(string filePath)
        {
            try
            {
                _configuration.SaveToFile(filePath);
                LogInfo($"Configuration saved to {filePath}");
            }
            catch (Exception ex)
            {
                LogError($"Error saving configuration: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Loads configuration from a file
        /// </summary>
        /// <param name="filePath">Path to the configuration file</param>
        /// <returns>True if loaded successfully, false otherwise</returns>
        public bool LoadConfiguration(string filePath)
        {
            try
            {
                bool wasMonitoring = IsMonitoring;

                // Stop monitoring if active
                if (wasMonitoring)
                {
                    StopMonitoring();
                }

                // Load configuration
                bool result = _configuration.LoadFromFile(filePath);
                if (result)
                {
                    // Reinitialize with new configuration
                    Initialize();

                    // Restart monitoring if it was active
                    if (wasMonitoring)
                    {
                        StartMonitoring();
                    }

                    LogInfo($"Configuration loaded from {filePath}");
                }

                return result;
            }
            catch (Exception ex)
            {
                LogError($"Error loading configuration: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the monitoring components with the current configuration
        /// </summary>
        private void Initialize()
        {
            try
            {
                // Stop monitoring if active
                if (IsMonitoring)
                {
                    StopMonitoring();
                }

                // Clear existing paths and keys
                _fileMonitor.ClearMonitoredPaths();
                _registryMonitor.ClearMonitoredKeys();

                // Add configured paths to file monitor
                foreach (string path in _configuration.MonitoredPaths)
                {
                    try
                    {
                        _fileMonitor.AddMonitoredPath(path);
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"Error adding monitored path {path}: {ex.Message}");
                    }
                }

                // Add configured keys to registry monitor
                foreach (var keyPath in _configuration.MonitoredRegistryKeys)
                {
                    try
                    {
                        _registryMonitor.AddMonitoredKey(keyPath);
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"Error adding monitored registry key {keyPath.FullPath}: {ex.Message}");
                    }
                }

                // Set refresh interval
                _refreshTimer.Interval = _configuration.RefreshIntervalSeconds * 1000;

                // Set max changes to keep
                _fileMonitor.MaxChangesToKeep = _configuration.MaxChangesToKeep;
                _registryMonitor.MaxChangesToKeep = _configuration.MaxChangesToKeep;

                // Subscribe to change events
                _fileMonitor.FileChanged += OnFileChanged;
                _registryMonitor.RegistryChanged += OnRegistryChanged;

                _isInitialized = true;
                LogInfo("Monitoring components initialized");
            }
            catch (Exception ex)
            {
                _isInitialized = false;
                LogError($"Error initializing monitoring components: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates statistics based on current changes
        /// </summary>
        private void UpdateStatistics()
        {
            try
            {
                // Update file changes count
                TotalFileChanges = _fileMonitor.FileChanges.Count;

                // Update registry changes count
                TotalRegistryChanges = _registryMonitor.RegistryChanges.Count;

                // Update high severity changes count
                int highSeverityFileChanges = 0;
                int highSeverityRegistryChanges = 0;

                foreach (var change in _fileMonitor.FileChanges)
                {
                    if (change.Severity == ChangeSeverity.High)
                    {
                        highSeverityFileChanges++;
                    }
                }

                foreach (var change in _registryMonitor.RegistryChanges)
                {
                    if (change.Severity == ChangeSeverity.High)
                    {
                        highSeverityRegistryChanges++;
                    }
                }

                HighSeverityChanges = highSeverityFileChanges + highSeverityRegistryChanges;
            }
            catch (Exception ex)
            {
                LogError($"Error updating statistics: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the refresh timer elapsed event
        /// </summary>
        private void OnRefreshTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try
            {
                // Use Dispatcher to update UI from a non-UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    RefreshData();
                });
            }
            catch (Exception ex)
            {
                LogError($"Error in refresh timer: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the file changed event
        /// </summary>
        private void OnFileChanged(object sender, EventArgs e)
        {
            try
            {
                // Use Dispatcher to update UI from a non-UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    UpdateStatistics();
                });
            }
            catch (Exception ex)
            {
                LogError($"Error handling file change event: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the registry changed event
        /// </summary>
        private void OnRegistryChanged(object sender, EventArgs e)
        {
            try
            {
                // Use Dispatcher to update UI from a non-UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    UpdateStatistics();
                });
            }
            catch (Exception ex)
            {
                LogError($"Error handling registry change event: {ex.Message}");
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [FileRegistryMonitoringManager] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [FileRegistryMonitoringManager] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [FileRegistryMonitoringManager] {message}");
        }

        #endregion

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes resources used by the manager
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes resources used by the manager
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    StopMonitoring();

                    // Unsubscribe from events
                    _fileMonitor.FileChanged -= OnFileChanged;
                    _registryMonitor.RegistryChanged -= OnRegistryChanged;
                    _refreshTimer.Elapsed -= OnRefreshTimerElapsed;

                    // Dispose timers
                    _refreshTimer.Dispose();

                    // Dispose monitors
                    if (_fileMonitor is IDisposable fileMonitorDisposable)
                    {
                        fileMonitorDisposable.Dispose();
                    }

                    if (_registryMonitor is IDisposable registryMonitorDisposable)
                    {
                        registryMonitorDisposable.Dispose();
                    }
                }

                _isDisposed = true;
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~FileRegistryMonitoringManager()
        {
            Dispose(false);
        }

        #endregion
    }
}