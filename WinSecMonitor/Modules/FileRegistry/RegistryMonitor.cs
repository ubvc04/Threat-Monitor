using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Monitors registry key changes in specified locations
    /// </summary>
    public class RegistryMonitor : INotifyPropertyChanged
    {   
        #region Properties

        private ObservableCollection<RegistryChange> _registryChanges;
        /// <summary>
        /// Collection of detected registry changes
        /// </summary>
        public ObservableCollection<RegistryChange> RegistryChanges
        {
            get { return _registryChanges; }
            set
            {
                _registryChanges = value;
                OnPropertyChanged(nameof(RegistryChanges));
            }
        }

        private ObservableCollection<RegistryKeyPath> _monitoredKeys;
        /// <summary>
        /// Collection of registry keys being monitored
        /// </summary>
        public ObservableCollection<RegistryKeyPath> MonitoredKeys
        {
            get { return _monitoredKeys; }
            set
            {
                _monitoredKeys = value;
                OnPropertyChanged(nameof(MonitoredKeys));
            }
        }

        private bool _isMonitoring;
        /// <summary>
        /// Indicates if monitoring is currently active
        /// </summary>
        public bool IsMonitoring
        {
            get { return _isMonitoring; }
            set
            {
                _isMonitoring = value;
                OnPropertyChanged(nameof(IsMonitoring));
            }
        }

        #endregion

        #region Private Fields

        private Dictionary<string, RegistryKey> _openKeys;
        private Dictionary<string, Dictionary<string, object>> _keyValueCache;
        private Timer _scanTimer;
        private int _maxChangesToKeep = 1000;
        private readonly object _lockObject = new object();
        private readonly TimeSpan _scanInterval = TimeSpan.FromSeconds(10);

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the RegistryMonitor class
        /// </summary>
        public RegistryMonitor()
        {   
            _registryChanges = new ObservableCollection<RegistryChange>();
            _monitoredKeys = new ObservableCollection<RegistryKeyPath>();
            _openKeys = new Dictionary<string, RegistryKey>();
            _keyValueCache = new Dictionary<string, Dictionary<string, object>>();

            // Add default sensitive registry keys to monitor
            AddDefaultMonitoredKeys();
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring the specified registry keys
        /// </summary>
        public void StartMonitoring()
        {   
            try
            {   
                if (IsMonitoring)
                    return;

                // Open registry keys and cache initial values
                foreach (var keyPath in MonitoredKeys)
                {
                    try
                    {   
                        OpenAndCacheRegistryKey(keyPath);
                    }
                    catch (Exception ex)
                    {   
                        // Log error but continue with other keys
                        LogError($"Error opening registry key {keyPath.FullPath}: {ex.Message}");
                    }
                }

                // Start timer for periodic scanning
                _scanTimer = new Timer(ScanRegistryKeys, null, TimeSpan.Zero, _scanInterval);
                IsMonitoring = true;
                LogInfo("Registry monitoring started");
            }
            catch (Exception ex)
            {   
                LogError($"Error starting registry monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stops monitoring all registry keys
        /// </summary>
        public void StopMonitoring()
        {   
            try
            {   
                if (!IsMonitoring)
                    return;

                // Stop timer
                _scanTimer?.Dispose();
                _scanTimer = null;

                // Close all open registry keys
                foreach (var key in _openKeys.Values)
                {
                    key.Dispose();
                }

                _openKeys.Clear();
                _keyValueCache.Clear();
                IsMonitoring = false;
                LogInfo("Registry monitoring stopped");
            }
            catch (Exception ex)
            {   
                LogError($"Error stopping registry monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Adds a new registry key to monitor
        /// </summary>
        /// <param name="keyPath">Registry key path to monitor</param>
        public void AddMonitoredKey(RegistryKeyPath keyPath)
        {   
            try
            {   
                if (keyPath == null || string.IsNullOrWhiteSpace(keyPath.FullPath))
                {
                    LogWarning("Cannot add invalid registry key path");
                    return;
                }

                if (!MonitoredKeys.Any(k => k.FullPath == keyPath.FullPath))
                {
                    MonitoredKeys.Add(keyPath);
                    
                    // If already monitoring, open and cache the new key
                    if (IsMonitoring)
                    {
                        OpenAndCacheRegistryKey(keyPath);
                    }

                    LogInfo($"Added registry key to monitoring: {keyPath.FullPath}");
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error adding monitored registry key {keyPath.FullPath}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Removes a registry key from monitoring
        /// </summary>
        /// <param name="keyPath">Registry key path to remove</param>
        public void RemoveMonitoredKey(RegistryKeyPath keyPath)
        {   
            try
            {   
                var keyToRemove = MonitoredKeys.FirstOrDefault(k => k.FullPath == keyPath.FullPath);
                if (keyToRemove != null)
                {
                    MonitoredKeys.Remove(keyToRemove);
                    
                    // If monitoring, close and remove the key
                    if (IsMonitoring && _openKeys.ContainsKey(keyPath.FullPath))
                    {
                        _openKeys[keyPath.FullPath].Dispose();
                        _openKeys.Remove(keyPath.FullPath);
                        _keyValueCache.Remove(keyPath.FullPath);
                    }

                    LogInfo($"Removed registry key from monitoring: {keyPath.FullPath}");
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error removing monitored registry key {keyPath.FullPath}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Clears the list of registry changes
        /// </summary>
        public void ClearChanges()
        {   
            try
            {   
                RegistryChanges.Clear();
                LogInfo("Registry changes cleared");
            }
            catch (Exception ex)
            {   
                LogError($"Error clearing registry changes: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Exports the list of registry changes to a CSV file
        /// </summary>
        /// <param name="filePath">Path to save the CSV file</param>
        public void ExportChangesToCsv(string filePath)
        {   
            try
            {   
                using (var writer = new System.IO.StreamWriter(filePath))
                {
                    // Write header
                    writer.WriteLine("Timestamp,ChangeType,KeyPath,ValueName,OldValue,NewValue,Severity");
                    
                    // Write data
                    foreach (var change in RegistryChanges)
                    {
                        writer.WriteLine($"{change.Timestamp:yyyy-MM-dd HH:mm:ss},"
                            + $"{change.ChangeType},"
                            + $"\"{change.KeyPath}\","
                            + $"\"{change.ValueName}\","
                            + $"\"{change.OldValue}\","
                            + $"\"{change.NewValue}\","
                            + $"{change.Severity}");
                    }
                }

                LogInfo($"Exported registry changes to {filePath}");
            }
            catch (Exception ex)
            {   
                LogError($"Error exporting registry changes to {filePath}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Forces an immediate scan of all monitored registry keys
        /// </summary>
        public void ForceRefresh()
        {   
            try
            {   
                if (!IsMonitoring)
                    return;

                ScanRegistryKeys(null);
                LogInfo("Forced registry scan completed");
            }
            catch (Exception ex)
            {   
                LogError($"Error during forced registry scan: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Adds default sensitive registry keys to monitor
        /// </summary>
        private void AddDefaultMonitoredKeys()
        {   
            try
            {   
                // Run keys (startup programs)
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.CurrentUser, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
                
                // Windows services
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Services"));
                
                // Security settings
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"));
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Lsa"));
                
                // Boot configuration
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Control\\Session Manager"));
                
                // Firewall settings
                MonitoredKeys.Add(new RegistryKeyPath(RegistryHive.LocalMachine, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"));
            }
            catch (Exception ex)
            {   
                LogError($"Error adding default monitored registry keys: {ex.Message}");
            }
        }

        /// <summary>
        /// Opens a registry key and caches its values
        /// </summary>
        /// <param name="keyPath">Registry key path to open</param>
        private void OpenAndCacheRegistryKey(RegistryKeyPath keyPath)
        {   
            try
            {   
                // Get root key based on hive
                RegistryKey rootKey = GetRootKey(keyPath.Hive);
                if (rootKey == null)
                {
                    LogWarning($"Invalid registry hive: {keyPath.Hive}");
                    return;
                }

                // Open the key
                RegistryKey key = rootKey.OpenSubKey(keyPath.SubKeyPath, false);
                if (key == null)
                {
                    LogWarning($"Registry key not found: {keyPath.FullPath}");
                    return;
                }

                // Store the open key
                _openKeys[keyPath.FullPath] = key;

                // Cache the key's values
                CacheKeyValues(keyPath.FullPath, key);
            }
            catch (SecurityException ex)
            {   
                LogError($"Access denied to registry key {keyPath.FullPath}: {ex.Message}");
            }
            catch (Exception ex)
            {   
                LogError($"Error opening registry key {keyPath.FullPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Caches the values of a registry key
        /// </summary>
        /// <param name="keyPath">Full path of the registry key</param>
        /// <param name="key">Open registry key</param>
        private void CacheKeyValues(string keyPath, RegistryKey key)
        {   
            try
            {   
                Dictionary<string, object> values = new Dictionary<string, object>();

                // Get all value names
                string[] valueNames = key.GetValueNames();
                foreach (string valueName in valueNames)
                {
                    try
                    {   
                        // Get the value and store it in the cache
                        object value = key.GetValue(valueName);
                        values[valueName] = value;
                    }
                    catch (Exception ex)
                    {   
                        LogError($"Error reading registry value {keyPath}\\{valueName}: {ex.Message}");
                    }
                }

                // Store the values in the cache
                _keyValueCache[keyPath] = values;

                // Also monitor subkeys if this is a parent key we're watching
                if (MonitoredKeys.Any(k => k.FullPath == keyPath && k.IncludeSubKeys))
                {
                    try
                    {   
                        string[] subKeyNames = key.GetSubKeyNames();
                        foreach (string subKeyName in subKeyNames)
                        {
                            try
                            {   
                                string subKeyPath = $"{keyPath}\\{subKeyName}";
                                RegistryKey subKey = key.OpenSubKey(subKeyName, false);
                                if (subKey != null)
                                {
                                    _openKeys[subKeyPath] = subKey;
                                    CacheKeyValues(subKeyPath, subKey);
                                }
                            }
                            catch (Exception ex)
                            {   
                                LogError($"Error opening subkey {keyPath}\\{subKeyName}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {   
                        LogError($"Error enumerating subkeys for {keyPath}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error caching registry values for {keyPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Scans all monitored registry keys for changes
        /// </summary>
        private void ScanRegistryKeys(object state)
        {   
            try
            {   
                // Make a copy of the keys to scan to avoid modification during enumeration
                Dictionary<string, RegistryKey> keysToScan;
                lock (_lockObject)
                {
                    keysToScan = new Dictionary<string, RegistryKey>(_openKeys);
                }

                foreach (var entry in keysToScan)
                {
                    try
                    {   
                        string keyPath = entry.Key;
                        RegistryKey key = entry.Value;

                        // Skip if we don't have a cached version to compare against
                        if (!_keyValueCache.ContainsKey(keyPath))
                            continue;

                        // Get the cached values
                        Dictionary<string, object> cachedValues = _keyValueCache[keyPath];

                        // Get current value names
                        string[] currentValueNames;
                        try
                        {   
                            currentValueNames = key.GetValueNames();
                        }
                        catch (Exception ex)
                        {   
                            LogError($"Error reading value names for {keyPath}: {ex.Message}");
                            continue;
                        }

                        // Check for new or modified values
                        foreach (string valueName in currentValueNames)
                        {
                            try
                            {   
                                object currentValue = key.GetValue(valueName);
                                
                                // Check if this is a new value
                                if (!cachedValues.ContainsKey(valueName))
                                {
                                    // New value added
                                    AddRegistryChange(new RegistryChange
                                    {
                                        Timestamp = DateTime.Now,
                                        ChangeType = "Added",
                                        KeyPath = keyPath,
                                        ValueName = valueName,
                                        NewValue = FormatRegistryValue(currentValue),
                                        Severity = DetermineSeverity(keyPath, valueName, null, currentValue)
                                    });

                                    // Update cache
                                    cachedValues[valueName] = currentValue;
                                }
                                // Check if value has changed
                                else if (!RegistryValuesEqual(cachedValues[valueName], currentValue))
                                {
                                    // Value modified
                                    AddRegistryChange(new RegistryChange
                                    {
                                        Timestamp = DateTime.Now,
                                        ChangeType = "Modified",
                                        KeyPath = keyPath,
                                        ValueName = valueName,
                                        OldValue = FormatRegistryValue(cachedValues[valueName]),
                                        NewValue = FormatRegistryValue(currentValue),
                                        Severity = DetermineSeverity(keyPath, valueName, cachedValues[valueName], currentValue)
                                    });

                                    // Update cache
                                    cachedValues[valueName] = currentValue;
                                }
                            }
                            catch (Exception ex)
                            {   
                                LogError($"Error checking registry value {keyPath}\\{valueName}: {ex.Message}");
                            }
                        }

                        // Check for deleted values
                        List<string> deletedValues = cachedValues.Keys.Except(currentValueNames).ToList();
                        foreach (string valueName in deletedValues)
                        {   
                            // Value deleted
                            AddRegistryChange(new RegistryChange
                            {
                                Timestamp = DateTime.Now,
                                ChangeType = "Deleted",
                                KeyPath = keyPath,
                                ValueName = valueName,
                                OldValue = FormatRegistryValue(cachedValues[valueName]),
                                Severity = DetermineSeverity(keyPath, valueName, cachedValues[valueName], null)
                            });

                            // Remove from cache
                            cachedValues.Remove(valueName);
                        }

                        // Check for new subkeys if this is a parent key we're watching
                        if (MonitoredKeys.Any(k => k.FullPath == keyPath && k.IncludeSubKeys))
                        {
                            try
                            {   
                                string[] currentSubKeyNames = key.GetSubKeyNames();
                                
                                // Find new subkeys
                                foreach (string subKeyName in currentSubKeyNames)
                                {
                                    string subKeyPath = $"{keyPath}\\{subKeyName}";
                                    if (!_openKeys.ContainsKey(subKeyPath))
                                    {
                                        try
                                        {   
                                            // New subkey found, open and cache it
                                            RegistryKey subKey = key.OpenSubKey(subKeyName, false);
                                            if (subKey != null)
                                            {
                                                _openKeys[subKeyPath] = subKey;
                                                CacheKeyValues(subKeyPath, subKey);
                                                
                                                // Add change record
                                                AddRegistryChange(new RegistryChange
                                                {
                                                    Timestamp = DateTime.Now,
                                                    ChangeType = "SubKeyAdded",
                                                    KeyPath = keyPath,
                                                    ValueName = subKeyName,
                                                    Severity = DetermineSeverity(keyPath, subKeyName, null, null)
                                                });
                                            }
                                        }
                                        catch (Exception ex)
                                        {   
                                            LogError($"Error opening new subkey {subKeyPath}: {ex.Message}");
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {   
                                LogError($"Error checking for new subkeys in {keyPath}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {   
                        LogError($"Error scanning registry key {entry.Key}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error during registry scan: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds a registry change to the collection
        /// </summary>
        /// <param name="change">The registry change to add</param>
        private void AddRegistryChange(RegistryChange change)
        {   
            try
            {   
                // Use dispatcher to update ObservableCollection from any thread
                App.Current.Dispatcher.Invoke(() =>
                {
                    lock (_lockObject)
                    {
                        // Add to beginning of list (newest first)
                        RegistryChanges.Insert(0, change);

                        // Trim list if it exceeds maximum size
                        while (RegistryChanges.Count > _maxChangesToKeep)
                        {
                            RegistryChanges.RemoveAt(RegistryChanges.Count - 1);
                        }
                    }
                });

                LogInfo($"Registry {change.ChangeType}: {change.KeyPath}\\{change.ValueName} (Severity: {change.Severity})");
            }
            catch (Exception ex)
            {   
                LogError($"Error adding registry change: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines the severity level of a registry change
        /// </summary>
        /// <param name="keyPath">Registry key path</param>
        /// <param name="valueName">Registry value name</param>
        /// <param name="oldValue">Old value (null for new values)</param>
        /// <param name="newValue">New value (null for deleted values)</param>
        /// <returns>Severity level (Low, Medium, High, Critical)</returns>
        private string DetermineSeverity(string keyPath, string valueName, object oldValue, object newValue)
        {   
            try
            {   
                string keyPathLower = keyPath.ToLower();
                string valueNameLower = valueName?.ToLower() ?? string.Empty;

                // Critical system settings
                if (keyPathLower.Contains("\\lsa") || 
                    keyPathLower.Contains("\\sam") || 
                    keyPathLower.Contains("\\security") ||
                    keyPathLower.Contains("\\bootcfg") ||
                    keyPathLower.Contains("\\session manager"))
                {
                    return "Critical";
                }

                // Startup locations
                if (keyPathLower.Contains("\\run") || 
                    keyPathLower.Contains("\\runonce") || 
                    keyPathLower.Contains("\\services"))
                {
                    return "High";
                }

                // Security policies
                if (keyPathLower.Contains("\\policies") || 
                    keyPathLower.Contains("\\firewallpolicy") || 
                    keyPathLower.Contains("\\winlogon"))
                {
                    return "Medium";
                }

                // Default severity
                return "Low";
            }
            catch (Exception ex)
            {   
                LogError($"Error determining severity for {keyPath}\\{valueName}: {ex.Message}");
                return "Low"; // Default to low on error
            }
        }

        /// <summary>
        /// Gets the root registry key for a hive
        /// </summary>
        /// <param name="hive">Registry hive</param>
        /// <returns>Root registry key</returns>
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
                    return null;
            }
        }

        /// <summary>
        /// Compares two registry values for equality
        /// </summary>
        /// <param name="value1">First value</param>
        /// <param name="value2">Second value</param>
        /// <returns>True if values are equal</returns>
        private bool RegistryValuesEqual(object value1, object value2)
        {   
            try
            {   
                // Handle null values
                if (value1 == null && value2 == null)
                    return true;
                if (value1 == null || value2 == null)
                    return false;

                // Handle byte arrays
                if (value1 is byte[] bytes1 && value2 is byte[] bytes2)
                {
                    if (bytes1.Length != bytes2.Length)
                        return false;

                    for (int i = 0; i < bytes1.Length; i++)
                    {
                        if (bytes1[i] != bytes2[i])
                            return false;
                    }

                    return true;
                }

                // Handle string arrays
                if (value1 is string[] strings1 && value2 is string[] strings2)
                {
                    if (strings1.Length != strings2.Length)
                        return false;

                    for (int i = 0; i < strings1.Length; i++)
                    {
                        if (strings1[i] != strings2[i])
                            return false;
                    }

                    return true;
                }

                // Default comparison
                return value1.Equals(value2);
            }
            catch (Exception ex)
            {   
                LogError($"Error comparing registry values: {ex.Message}");
                return false; // Assume not equal on error
            }
        }

        /// <summary>
        /// Formats a registry value for display
        /// </summary>
        /// <param name="value">Registry value</param>
        /// <returns>Formatted string representation</returns>
        private string FormatRegistryValue(object value)
        {   
            try
            {   
                if (value == null)
                    return "(null)";

                // Handle byte arrays (binary data)
                if (value is byte[] bytes)
                {
                    if (bytes.Length > 20)
                    {
                        // Truncate long binary data
                        return $"(Binary data, {bytes.Length} bytes)";
                    }
                    else
                    {
                        // Show hex representation for small binary data
                        return "0x" + BitConverter.ToString(bytes).Replace("-", "");
                    }
                }

                // Handle string arrays
                if (value is string[] strings)
                {
                    return string.Join(", ", strings);
                }

                // Default to string representation
                return value.ToString();
            }
            catch (Exception ex)
            {   
                LogError($"Error formatting registry value: {ex.Message}");
                return "(Error formatting value)"; // Default on error
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private void LogInfo(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [RegistryMonitor] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private void LogWarning(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [RegistryMonitor] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private void LogError(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [RegistryMonitor] {message}");
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
    /// Represents a registry key path with hive and subkey path
    /// </summary>
    public class RegistryKeyPath : INotifyPropertyChanged
    {   
        private RegistryHive _hive;
        public RegistryHive Hive
        {
            get { return _hive; }
            set
            {
                _hive = value;
                OnPropertyChanged(nameof(Hive));
                OnPropertyChanged(nameof(FullPath));
            }
        }

        private string _subKeyPath;
        public string SubKeyPath
        {
            get { return _subKeyPath; }
            set
            {
                _subKeyPath = value;
                OnPropertyChanged(nameof(SubKeyPath));
                OnPropertyChanged(nameof(FullPath));
            }
        }

        private bool _includeSubKeys;
        public bool IncludeSubKeys
        {
            get { return _includeSubKeys; }
            set
            {
                _includeSubKeys = value;
                OnPropertyChanged(nameof(IncludeSubKeys));
            }
        }

        /// <summary>
        /// Gets the full registry key path
        /// </summary>
        public string FullPath
        {
            get { return $"{Hive}\\{SubKeyPath}"; }
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public RegistryKeyPath()
        {   
            _includeSubKeys = true;
        }

        /// <summary>
        /// Constructor with hive and subkey path
        /// </summary>
        public RegistryKeyPath(RegistryHive hive, string subKeyPath, bool includeSubKeys = true)
        {   
            _hive = hive;
            _subKeyPath = subKeyPath;
            _includeSubKeys = includeSubKeys;
        }

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {   
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    /// <summary>
    /// Represents a registry change detected by the RegistryMonitor
    /// </summary>
    public class RegistryChange : INotifyPropertyChanged
    {   
        private DateTime _timestamp;
        public DateTime Timestamp
        {
            get { return _timestamp; }
            set
            {
                _timestamp = value;
                OnPropertyChanged(nameof(Timestamp));
            }
        }

        private string _changeType;
        public string ChangeType
        {
            get { return _changeType; }
            set
            {
                _changeType = value;
                OnPropertyChanged(nameof(ChangeType));
            }
        }

        private string _keyPath;
        public string KeyPath
        {
            get { return _keyPath; }
            set
            {
                _keyPath = value;
                OnPropertyChanged(nameof(KeyPath));
            }
        }

        private string _valueName;
        public string ValueName
        {
            get { return _valueName; }
            set
            {
                _valueName = value;
                OnPropertyChanged(nameof(ValueName));
            }
        }

        private string _oldValue;
        public string OldValue
        {
            get { return _oldValue; }
            set
            {
                _oldValue = value;
                OnPropertyChanged(nameof(OldValue));
            }
        }

        private string _newValue;
        public string NewValue
        {
            get { return _newValue; }
            set
            {
                _newValue = value;
                OnPropertyChanged(nameof(NewValue));
            }
        }

        private string _severity;
        public string Severity
        {
            get { return _severity; }
            set
            {
                _severity = value;
                OnPropertyChanged(nameof(Severity));
            }
        }

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {   
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}