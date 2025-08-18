using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Xml.Serialization;
using Microsoft.Win32;

namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Manages configuration for file and registry monitoring
    /// </summary>
    public class FileRegistryConfiguration : INotifyPropertyChanged
    {
        #region Properties

        private ObservableCollection<string> _monitoredPaths;
        /// <summary>
        /// Collection of file system paths to monitor
        /// </summary>
        public ObservableCollection<string> MonitoredPaths
        {
            get { return _monitoredPaths; }
            set
            {
                _monitoredPaths = value;
                OnPropertyChanged(nameof(MonitoredPaths));
            }
        }

        private ObservableCollection<RegistryKeyPath> _monitoredRegistryKeys;
        /// <summary>
        /// Collection of registry keys to monitor
        /// </summary>
        public ObservableCollection<RegistryKeyPath> MonitoredRegistryKeys
        {
            get { return _monitoredRegistryKeys; }
            set
            {
                _monitoredRegistryKeys = value;
                OnPropertyChanged(nameof(MonitoredRegistryKeys));
            }
        }

        private int _refreshIntervalSeconds;
        /// <summary>
        /// Refresh interval for registry monitoring in seconds
        /// </summary>
        public int RefreshIntervalSeconds
        {
            get { return _refreshIntervalSeconds; }
            set
            {
                _refreshIntervalSeconds = value;
                OnPropertyChanged(nameof(RefreshIntervalSeconds));
            }
        }

        private bool _enableFileMonitoring;
        /// <summary>
        /// Indicates if file monitoring is enabled
        /// </summary>
        public bool EnableFileMonitoring
        {
            get { return _enableFileMonitoring; }
            set
            {
                _enableFileMonitoring = value;
                OnPropertyChanged(nameof(EnableFileMonitoring));
            }
        }

        private bool _enableRegistryMonitoring;
        /// <summary>
        /// Indicates if registry monitoring is enabled
        /// </summary>
        public bool EnableRegistryMonitoring
        {
            get { return _enableRegistryMonitoring; }
            set
            {
                _enableRegistryMonitoring = value;
                OnPropertyChanged(nameof(EnableRegistryMonitoring));
            }
        }

        private int _maxChangesToKeep;
        /// <summary>
        /// Maximum number of changes to keep in history
        /// </summary>
        public int MaxChangesToKeep
        {
            get { return _maxChangesToKeep; }
            set
            {
                _maxChangesToKeep = value;
                OnPropertyChanged(nameof(MaxChangesToKeep));
            }
        }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the FileRegistryConfiguration class
        /// </summary>
        public FileRegistryConfiguration()
        {
            // Initialize collections
            _monitoredPaths = new ObservableCollection<string>();
            _monitoredRegistryKeys = new ObservableCollection<RegistryKeyPath>();

            // Set default values
            _refreshIntervalSeconds = 10;
            _enableFileMonitoring = true;
            _enableRegistryMonitoring = true;
            _maxChangesToKeep = 1000;

            // Load default configuration
            LoadDefaultConfiguration();
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Saves the configuration to an XML file
        /// </summary>
        /// <param name="filePath">Path to save the configuration file</param>
        public void SaveToFile(string filePath)
        {
            try
            {
                // Create serializable configuration
                var config = new SerializableConfiguration
                {
                    MonitoredPaths = MonitoredPaths.ToList(),
                    MonitoredRegistryKeys = ConvertToSerializableRegistryKeys(MonitoredRegistryKeys),
                    RefreshIntervalSeconds = RefreshIntervalSeconds,
                    EnableFileMonitoring = EnableFileMonitoring,
                    EnableRegistryMonitoring = EnableRegistryMonitoring,
                    MaxChangesToKeep = MaxChangesToKeep
                };

                // Serialize to XML
                var serializer = new XmlSerializer(typeof(SerializableConfiguration));
                using (var writer = new StreamWriter(filePath))
                {
                    serializer.Serialize(writer, config);
                }

                LogInfo($"Configuration saved to {filePath}");
            }
            catch (Exception ex)
            {
                LogError($"Error saving configuration to {filePath}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Loads the configuration from an XML file
        /// </summary>
        /// <param name="filePath">Path to the configuration file</param>
        /// <returns>True if loaded successfully, false otherwise</returns>
        public bool LoadFromFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    LogWarning($"Configuration file not found: {filePath}");
                    return false;
                }

                // Deserialize from XML
                var serializer = new XmlSerializer(typeof(SerializableConfiguration));
                using (var reader = new StreamReader(filePath))
                {
                    var config = (SerializableConfiguration)serializer.Deserialize(reader);

                    // Update properties
                    MonitoredPaths = new ObservableCollection<string>(config.MonitoredPaths);
                    MonitoredRegistryKeys = ConvertFromSerializableRegistryKeys(config.MonitoredRegistryKeys);
                    RefreshIntervalSeconds = config.RefreshIntervalSeconds;
                    EnableFileMonitoring = config.EnableFileMonitoring;
                    EnableRegistryMonitoring = config.EnableRegistryMonitoring;
                    MaxChangesToKeep = config.MaxChangesToKeep;
                }

                LogInfo($"Configuration loaded from {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error loading configuration from {filePath}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Adds a file system path to monitor
        /// </summary>
        /// <param name="path">Directory path to monitor</param>
        /// <returns>True if added successfully, false if already exists or invalid</returns>
        public bool AddMonitoredPath(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    LogWarning("Cannot add empty path");
                    return false;
                }

                if (!Directory.Exists(path))
                {
                    LogWarning($"Directory does not exist: {path}");
                    return false;
                }

                if (MonitoredPaths.Contains(path))
                {
                    LogWarning($"Path already being monitored: {path}");
                    return false;
                }

                MonitoredPaths.Add(path);
                LogInfo($"Added path to monitoring: {path}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error adding monitored path {path}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Removes a file system path from monitoring
        /// </summary>
        /// <param name="path">Directory path to remove</param>
        /// <returns>True if removed successfully, false if not found</returns>
        public bool RemoveMonitoredPath(string path)
        {
            try
            {
                if (!MonitoredPaths.Contains(path))
                {
                    LogWarning($"Path not found in monitored paths: {path}");
                    return false;
                }

                MonitoredPaths.Remove(path);
                LogInfo($"Removed path from monitoring: {path}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error removing monitored path {path}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Adds a registry key to monitor
        /// </summary>
        /// <param name="keyPath">Registry key path to monitor</param>
        /// <returns>True if added successfully, false if already exists or invalid</returns>
        public bool AddMonitoredRegistryKey(RegistryKeyPath keyPath)
        {
            try
            {
                if (keyPath == null || string.IsNullOrWhiteSpace(keyPath.SubKeyPath))
                {
                    LogWarning("Cannot add invalid registry key path");
                    return false;
                }

                if (MonitoredRegistryKeys.Any(k => k.FullPath == keyPath.FullPath))
                {
                    LogWarning($"Registry key already being monitored: {keyPath.FullPath}");
                    return false;
                }

                // Verify the key exists
                try
                {
                    var rootKey = GetRootKey(keyPath.Hive);
                    using (var key = rootKey.OpenSubKey(keyPath.SubKeyPath))
                    {
                        if (key == null)
                        {
                            LogWarning($"Registry key does not exist: {keyPath.FullPath}");
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Error verifying registry key {keyPath.FullPath}: {ex.Message}");
                    return false;
                }

                MonitoredRegistryKeys.Add(keyPath);
                LogInfo($"Added registry key to monitoring: {keyPath.FullPath}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error adding monitored registry key {keyPath?.FullPath}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Removes a registry key from monitoring
        /// </summary>
        /// <param name="keyPath">Registry key path to remove</param>
        /// <returns>True if removed successfully, false if not found</returns>
        public bool RemoveMonitoredRegistryKey(RegistryKeyPath keyPath)
        {
            try
            {
                var keyToRemove = MonitoredRegistryKeys.FirstOrDefault(k => k.FullPath == keyPath.FullPath);
                if (keyToRemove == null)
                {
                    LogWarning($"Registry key not found in monitored keys: {keyPath.FullPath}");
                    return false;
                }

                MonitoredRegistryKeys.Remove(keyToRemove);
                LogInfo($"Removed registry key from monitoring: {keyPath.FullPath}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error removing monitored registry key {keyPath?.FullPath}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Resets the configuration to default values
        /// </summary>
        public void ResetToDefaults()
        {
            try
            {
                MonitoredPaths.Clear();
                MonitoredRegistryKeys.Clear();
                RefreshIntervalSeconds = 10;
                EnableFileMonitoring = true;
                EnableRegistryMonitoring = true;
                MaxChangesToKeep = 1000;

                LoadDefaultConfiguration();
                LogInfo("Configuration reset to defaults");
            }
            catch (Exception ex)
            {
                LogError($"Error resetting configuration to defaults: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Loads the default configuration
        /// </summary>
        private void LoadDefaultConfiguration()
        {
            try
            {
                // Default file system paths to monitor
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"));
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"));
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup)));
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)));
                MonitoredPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));

                // Default registry keys to monitor
                MonitoredRegistryKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
                MonitoredRegistryKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
                MonitoredRegistryKeys.Add(new RegistryKeyPath(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
                MonitoredRegistryKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Services"));
                MonitoredRegistryKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"));
            }
            catch (Exception ex)
            {
                LogError($"Error loading default configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Converts ObservableCollection of RegistryKeyPath to List of SerializableRegistryKeyPath
        /// </summary>
        private List<SerializableRegistryKeyPath> ConvertToSerializableRegistryKeys(ObservableCollection<RegistryKeyPath> keys)
        {
            return keys.Select(k => new SerializableRegistryKeyPath
            {
                Hive = k.Hive,
                SubKeyPath = k.SubKeyPath,
                IncludeSubKeys = k.IncludeSubKeys
            }).ToList();
        }

        /// <summary>
        /// Converts List of SerializableRegistryKeyPath to ObservableCollection of RegistryKeyPath
        /// </summary>
        private ObservableCollection<RegistryKeyPath> ConvertFromSerializableRegistryKeys(List<SerializableRegistryKeyPath> keys)
        {
            return new ObservableCollection<RegistryKeyPath>(
                keys.Select(k => new RegistryKeyPath(k.Hive, k.SubKeyPath, k.IncludeSubKeys))
            );
        }

        /// <summary>
        /// Gets the root registry key for a hive
        /// </summary>
        private RegistryKey GetRootKey(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:
                    return Registry.ClassesRoot;
                case RegistryHive.CurrentUser:
                    return Registry.CurrentUser;
                case RegistryHive.LocalMachine:
                    return Registry.LocalMachine;
                case RegistryHive.Users:
                    return Registry.Users;
                case RegistryHive.CurrentConfig:
                    return Registry.CurrentConfig;
                default:
                    throw new ArgumentException($"Invalid registry hive: {hive}");
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [FileRegistryConfiguration] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [FileRegistryConfiguration] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [FileRegistryConfiguration] {message}");
        }

        #endregion

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    /// <summary>
    /// Serializable configuration class for XML serialization
    /// </summary>
    [Serializable]
    public class SerializableConfiguration
    {
        public List<string> MonitoredPaths { get; set; } = new List<string>();
        public List<SerializableRegistryKeyPath> MonitoredRegistryKeys { get; set; } = new List<SerializableRegistryKeyPath>();
        public int RefreshIntervalSeconds { get; set; } = 10;
        public bool EnableFileMonitoring { get; set; } = true;
        public bool EnableRegistryMonitoring { get; set; } = true;
        public int MaxChangesToKeep { get; set; } = 1000;
    }

    /// <summary>
    /// Serializable registry key path for XML serialization
    /// </summary>
    [Serializable]
    public class SerializableRegistryKeyPath
    {
        public RegistryHive Hive { get; set; }
        public string SubKeyPath { get; set; }
        public bool IncludeSubKeys { get; set; } = true;
    }
}