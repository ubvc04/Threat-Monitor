using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Permissions;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security;

namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Monitors file system changes in specified directories
    /// </summary>
    public class FileMonitor : INotifyPropertyChanged
    {   
        #region Properties

        private ObservableCollection<FileSystemChange> _fileChanges;
        /// <summary>
        /// Collection of detected file system changes
        /// </summary>
        public ObservableCollection<FileSystemChange> FileChanges
        {
            get { return _fileChanges; }
            set
            {
                _fileChanges = value;
                OnPropertyChanged(nameof(FileChanges));
            }
        }

        private ObservableCollection<string> _monitoredPaths;
        /// <summary>
        /// Collection of paths being monitored
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

        private List<FileSystemWatcher> _watchers;
        private int _maxChangesToKeep = 1000;
        private readonly object _lockObject = new object();
        private readonly Dictionary<string, DateTime> _lastProcessedChanges = new Dictionary<string, DateTime>();
        private readonly TimeSpan _changeThrottleTime = TimeSpan.FromMilliseconds(500); // Prevent duplicate events

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the FileMonitor class
        /// </summary>
        public FileMonitor()
        {
            _fileChanges = new ObservableCollection<FileSystemChange>();
            _monitoredPaths = new ObservableCollection<string>();
            _watchers = new List<FileSystemWatcher>();

            // Add default sensitive directories to monitor
            AddDefaultMonitoredPaths();
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring the specified directories
        /// </summary>
        public void StartMonitoring()
        {
            try
            {   
                if (IsMonitoring)
                    return;

                // Create watchers for each path
                foreach (string path in MonitoredPaths)
                {
                    try
                    {
                        CreateWatcherForPath(path);
                    }
                    catch (Exception ex)
                    {   
                        // Log error but continue with other paths
                        LogError($"Error creating watcher for path {path}: {ex.Message}");
                    }
                }

                IsMonitoring = true;
                LogInfo("File monitoring started");
            }
            catch (Exception ex)
            {   
                LogError($"Error starting file monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stops monitoring all directories
        /// </summary>
        public void StopMonitoring()
        {
            try
            {   
                if (!IsMonitoring)
                    return;

                // Dispose all watchers
                foreach (var watcher in _watchers)
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Created -= OnFileChanged;
                    watcher.Changed -= OnFileChanged;
                    watcher.Deleted -= OnFileChanged;
                    watcher.Renamed -= OnFileRenamed;
                    watcher.Error -= OnWatcherError;
                    watcher.Dispose();
                }

                _watchers.Clear();
                IsMonitoring = false;
                LogInfo("File monitoring stopped");
            }
            catch (Exception ex)
            {   
                LogError($"Error stopping file monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Adds a new path to monitor
        /// </summary>
        /// <param name="path">Directory path to monitor</param>
        public void AddMonitoredPath(string path)
        {   
            try
            {   
                if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
                {
                    LogWarning($"Cannot add invalid or non-existent path: {path}");
                    return;
                }

                if (!MonitoredPaths.Contains(path))
                {
                    MonitoredPaths.Add(path);
                    
                    // If already monitoring, create a watcher for the new path
                    if (IsMonitoring)
                    {
                        CreateWatcherForPath(path);
                    }

                    LogInfo($"Added path to monitoring: {path}");
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error adding monitored path {path}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Removes a path from monitoring
        /// </summary>
        /// <param name="path">Directory path to remove</param>
        public void RemoveMonitoredPath(string path)
        {   
            try
            {   
                if (MonitoredPaths.Contains(path))
                {
                    MonitoredPaths.Remove(path);
                    
                    // If monitoring, remove and dispose the watcher for this path
                    if (IsMonitoring)
                    {
                        var watchersToRemove = _watchers.Where(w => w.Path == path).ToList();
                        foreach (var watcher in watchersToRemove)
                        {
                            watcher.EnableRaisingEvents = false;
                            watcher.Dispose();
                            _watchers.Remove(watcher);
                        }
                    }

                    LogInfo($"Removed path from monitoring: {path}");
                }
            }
            catch (Exception ex)
            {   
                LogError($"Error removing monitored path {path}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Clears the list of file changes
        /// </summary>
        public void ClearChanges()
        {   
            try
            {   
                FileChanges.Clear();
                LogInfo("File changes cleared");
            }
            catch (Exception ex)
            {   
                LogError($"Error clearing file changes: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Exports the list of file changes to a CSV file
        /// </summary>
        /// <param name="filePath">Path to save the CSV file</param>
        public void ExportChangesToCsv(string filePath)
        {   
            try
            {   
                using (var writer = new StreamWriter(filePath))
                {
                    // Write header
                    writer.WriteLine("Timestamp,ChangeType,Path,OldPath,Severity");
                    
                    // Write data
                    foreach (var change in FileChanges)
                    {
                        writer.WriteLine($"{change.Timestamp:yyyy-MM-dd HH:mm:ss},"
                            + $"{change.ChangeType},"
                            + $"\"{change.Path}\","
                            + $"\"{change.OldPath}\","
                            + $"{change.Severity}");
                    }
                }

                LogInfo($"Exported file changes to {filePath}");
            }
            catch (Exception ex)
            {   
                LogError($"Error exporting file changes to {filePath}: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Adds default sensitive directories to monitor
        /// </summary>
        private void AddDefaultMonitoredPaths()
        {   
            try
            {   
                // System directories
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"));
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"));
                
                // Startup locations
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup)));
                MonitoredPaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)));
                
                // Program Files
                MonitoredPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                MonitoredPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            }
            catch (Exception ex)
            {   
                LogError($"Error adding default monitored paths: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates a FileSystemWatcher for the specified path
        /// </summary>
        /// <param name="path">Directory path to watch</param>
        private void CreateWatcherForPath(string path)
        {   
            try
            {   
                if (!Directory.Exists(path))
                {
                    LogWarning($"Cannot create watcher for non-existent path: {path}");
                    return;
                }

                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.Security,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                // Attach event handlers
                watcher.Created += OnFileChanged;
                watcher.Changed += OnFileChanged;
                watcher.Deleted += OnFileChanged;
                watcher.Renamed += OnFileRenamed;
                watcher.Error += OnWatcherError;

                _watchers.Add(watcher);
                LogInfo($"Created watcher for path: {path}");
            }
            catch (UnauthorizedAccessException ex)
            {   
                LogError($"Access denied when creating watcher for {path}: {ex.Message}");
            }
            catch (Exception ex)
            {   
                LogError($"Error creating watcher for {path}: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for file system changes (Created, Changed, Deleted)
        /// </summary>
        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {   
            try
            {   
                // Throttle duplicate events
                if (ShouldThrottleEvent(e.FullPath))
                    return;

                var changeType = e.ChangeType.ToString();
                var severity = DetermineSeverity(e.FullPath, changeType);

                AddFileChange(new FileSystemChange
                {
                    Timestamp = DateTime.Now,
                    ChangeType = changeType,
                    Path = e.FullPath,
                    Severity = severity
                });
            }
            catch (Exception ex)
            {   
                LogError($"Error processing file change event: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for file rename events
        /// </summary>
        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {   
            try
            {   
                // Throttle duplicate events
                if (ShouldThrottleEvent(e.FullPath))
                    return;

                var severity = DetermineSeverity(e.FullPath, "Renamed");

                AddFileChange(new FileSystemChange
                {
                    Timestamp = DateTime.Now,
                    ChangeType = "Renamed",
                    Path = e.FullPath,
                    OldPath = e.OldFullPath,
                    Severity = severity
                });
            }
            catch (Exception ex)
            {   
                LogError($"Error processing file rename event: {ex.Message}");
            }
        }

        /// <summary>
        /// Event handler for watcher errors
        /// </summary>
        private void OnWatcherError(object sender, ErrorEventArgs e)
        {   
            try
            {   
                var watcher = sender as FileSystemWatcher;
                var path = watcher?.Path ?? "Unknown path";

                LogError($"File system watcher error for {path}: {e.GetException().Message}");

                // Try to recreate the watcher after a delay
                Task.Delay(5000).ContinueWith(_ =>
                {
                    try
                    {
                        if (watcher != null && MonitoredPaths.Contains(watcher.Path))
                        {
                            watcher.EnableRaisingEvents = false;
                            watcher.Dispose();
                            _watchers.Remove(watcher);
                            CreateWatcherForPath(path);
                            LogInfo($"Recreated watcher for path: {path}");
                        }
                    }
                    catch (Exception ex)
                    {   
                        LogError($"Error recreating watcher for {path}: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {   
                LogError($"Error handling watcher error event: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds a file change to the collection
        /// </summary>
        /// <param name="change">The file system change to add</param>
        private void AddFileChange(FileSystemChange change)
        {   
            try
            {   
                // Use dispatcher to update ObservableCollection from any thread
                App.Current.Dispatcher.Invoke(() =>
                {
                    lock (_lockObject)
                    {
                        // Add to beginning of list (newest first)
                        FileChanges.Insert(0, change);

                        // Trim list if it exceeds maximum size
                        while (FileChanges.Count > _maxChangesToKeep)
                        {
                            FileChanges.RemoveAt(FileChanges.Count - 1);
                        }
                    }
                });

                // Update last processed time for this path
                lock (_lockObject)
                {
                    _lastProcessedChanges[change.Path] = DateTime.Now;
                }

                LogInfo($"File {change.ChangeType}: {change.Path} (Severity: {change.Severity})");
            }
            catch (Exception ex)
            {   
                LogError($"Error adding file change: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines if an event should be throttled to prevent duplicates
        /// </summary>
        /// <param name="path">File path that changed</param>
        /// <returns>True if the event should be throttled</returns>
        private bool ShouldThrottleEvent(string path)
        {   
            lock (_lockObject)
            {
                if (_lastProcessedChanges.TryGetValue(path, out DateTime lastTime))
                {
                    // If the same path was processed recently, throttle it
                    if ((DateTime.Now - lastTime) < _changeThrottleTime)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>
        /// Determines the severity level of a file change
        /// </summary>
        /// <param name="path">File path that changed</param>
        /// <param name="changeType">Type of change (Created, Changed, Deleted, Renamed)</param>
        /// <returns>Severity level (Low, Medium, High, Critical)</returns>
        private string DetermineSeverity(string path, string changeType)
        {   
            try
            {   
                // Check for system critical files
                if (IsCriticalSystemFile(path))
                {
                    return "Critical";
                }

                // Check for executable files
                if (IsExecutableFile(path))
                {
                    // Executable files in system directories or startup locations
                    if (IsInSystemDirectory(path) || IsInStartupLocation(path))
                    {
                        return changeType == "Deleted" ? "Medium" : "High";
                    }
                    // Other executable files
                    return "Medium";
                }

                // Check for configuration files
                if (IsConfigurationFile(path))
                {
                    return "Medium";
                }

                // Default severity
                return "Low";
            }
            catch (Exception ex)
            {   
                LogError($"Error determining severity for {path}: {ex.Message}");
                return "Low"; // Default to low on error
            }
        }

        /// <summary>
        /// Checks if a file is a critical system file
        /// </summary>
        private bool IsCriticalSystemFile(string path)
        {   
            try
            {   
                string fileName = Path.GetFileName(path).ToLower();
                string directory = Path.GetDirectoryName(path).ToLower();

                // Critical system files
                string[] criticalFiles = new string[] 
                { 
                    "ntoskrnl.exe", "hal.dll", "winload.exe", "bootmgr", "smss.exe",
                    "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                    "system", "sam", "security", "software"
                };

                if (criticalFiles.Contains(fileName))
                    return true;

                // Check for system32 drivers
                if (directory.Contains("\\system32\\drivers") && Path.GetExtension(path).ToLower() == ".sys")
                    return true;

                return false;
            }
            catch (Exception ex)
            {   
                LogError($"Error checking if {path} is a critical system file: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if a file is an executable
        /// </summary>
        private bool IsExecutableFile(string path)
        {   
            try
            {   
                string extension = Path.GetExtension(path).ToLower();
                return extension == ".exe" || extension == ".dll" || extension == ".sys" || 
                       extension == ".bat" || extension == ".cmd" || extension == ".ps1" || 
                       extension == ".vbs" || extension == ".js";
            }
            catch (Exception ex)
            {   
                LogError($"Error checking if {path} is an executable file: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if a file is a configuration file
        /// </summary>
        private bool IsConfigurationFile(string path)
        {   
            try
            {   
                string extension = Path.GetExtension(path).ToLower();
                return extension == ".ini" || extension == ".config" || extension == ".xml" || 
                       extension == ".json" || extension == ".reg";
            }
            catch (Exception ex)
            {   
                LogError($"Error checking if {path} is a configuration file: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if a file is in a system directory
        /// </summary>
        private bool IsInSystemDirectory(string path)
        {   
            try
            {   
                string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLower();
                string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
                string pathLower = path.ToLower();

                return pathLower.StartsWith(systemDir) || pathLower.StartsWith(windowsDir);
            }
            catch (Exception ex)
            {   
                LogError($"Error checking if {path} is in a system directory: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if a file is in a startup location
        /// </summary>
        private bool IsInStartupLocation(string path)
        {   
            try
            {   
                string startupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup).ToLower();
                string commonStartupDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup).ToLower();
                string pathLower = path.ToLower();

                return pathLower.StartsWith(startupDir) || pathLower.StartsWith(commonStartupDir);
            }
            catch (Exception ex)
            {   
                LogError($"Error checking if {path} is in a startup location: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private void LogInfo(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [FileMonitor] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private void LogWarning(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [FileMonitor] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private void LogError(string message)
        {   
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [FileMonitor] {message}");
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
    /// Represents a file system change detected by the FileMonitor
    /// </summary>
    public class FileSystemChange : INotifyPropertyChanged
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

        private string _path;
        public string Path
        {
            get { return _path; }
            set
            {
                _path = value;
                OnPropertyChanged(nameof(Path));
                // Also update FileName property
                FileName = System.IO.Path.GetFileName(value);
            }
        }

        private string _oldPath;
        public string OldPath
        {
            get { return _oldPath; }
            set
            {
                _oldPath = value;
                OnPropertyChanged(nameof(OldPath));
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

        private string _fileName;
        public string FileName
        {
            get { return _fileName; }
            set
            {
                _fileName = value;
                OnPropertyChanged(nameof(FileName));
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