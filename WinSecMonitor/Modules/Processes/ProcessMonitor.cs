using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Processes
{
    /// <summary>
    /// Monitors running processes on the system
    /// </summary>
    public class ProcessMonitor : INotifyPropertyChanged, IDisposable
    {
        #region Private Fields

        private readonly ObservableCollection<ProcessInfo> _processes;
        private readonly Dictionary<int, ProcessInfo> _processesById;
        private readonly HashSet<string> _knownSystemProcesses;
        private readonly HashSet<string> _whitelistedProcesses;
        private readonly Timer _refreshTimer;
        private readonly object _lockObject = new object();
        private bool _isMonitoring;
        private int _refreshInterval;
        private bool _disposedValue;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the collection of processes
        /// </summary>
        public ObservableCollection<ProcessInfo> Processes => _processes;

        /// <summary>
        /// Gets or sets whether monitoring is active
        /// </summary>
        public bool IsMonitoring
        {
            get { return _isMonitoring; }
            set
            {
                if (_isMonitoring != value)
                {
                    _isMonitoring = value;
                    OnPropertyChanged(nameof(IsMonitoring));

                    if (_isMonitoring)
                    {
                        StartMonitoring();
                    }
                    else
                    {
                        StopMonitoring();
                    }
                }
            }
        }

        /// <summary>
        /// Gets or sets the refresh interval in milliseconds
        /// </summary>
        public int RefreshInterval
        {
            get { return _refreshInterval; }
            set
            {
                if (_refreshInterval != value && value >= 1000)
                {
                    _refreshInterval = value;
                    OnPropertyChanged(nameof(RefreshInterval));

                    if (_isMonitoring)
                    {
                        _refreshTimer.Change(0, _refreshInterval);
                    }
                }
            }
        }

        /// <summary>
        /// Gets the number of unknown processes
        /// </summary>
        public int UnknownProcessCount => _processes.Count(p => p.IsUnknown);

        /// <summary>
        /// Gets the number of suspicious processes
        /// </summary>
        public int SuspiciousProcessCount => _processes.Count(p => p.IsSuspicious);

        #endregion

        #region Events

        /// <summary>
        /// Event raised when a new process is started
        /// </summary>
        public event EventHandler<ProcessEventArgs> ProcessStarted;

        /// <summary>
        /// Event raised when a process is terminated
        /// </summary>
        public event EventHandler<ProcessEventArgs> ProcessTerminated;

        /// <summary>
        /// Event raised when a suspicious process is detected
        /// </summary>
        public event EventHandler<ProcessEventArgs> SuspiciousProcessDetected;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the ProcessMonitor class
        /// </summary>
        public ProcessMonitor()
        {
            _processes = new ObservableCollection<ProcessInfo>();
            _processesById = new Dictionary<int, ProcessInfo>();
            _knownSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _refreshInterval = 5000; // 5 seconds default
            _refreshTimer = new Timer(RefreshProcesses, null, Timeout.Infinite, Timeout.Infinite);

            InitializeKnownProcesses();
            LogInfo("ProcessMonitor initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring processes
        /// </summary>
        public void StartMonitoring()
        {
            if (!_isMonitoring)
            {
                _isMonitoring = true;
                OnPropertyChanged(nameof(IsMonitoring));

                // Initial refresh
                RefreshProcesses(null);

                // Start timer
                _refreshTimer.Change(0, _refreshInterval);

                LogInfo("Process monitoring started");
            }
        }

        /// <summary>
        /// Stops monitoring processes
        /// </summary>
        public void StopMonitoring()
        {
            if (_isMonitoring)
            {
                _isMonitoring = false;
                OnPropertyChanged(nameof(IsMonitoring));

                // Stop timer
                _refreshTimer.Change(Timeout.Infinite, Timeout.Infinite);

                LogInfo("Process monitoring stopped");
            }
        }

        /// <summary>
        /// Refreshes the process list
        /// </summary>
        public void RefreshProcesses(object state)
        {
            try
            {
                lock (_lockObject)
                {
                    // Get current processes
                    var currentProcesses = Process.GetProcesses();
                    var currentProcessIds = new HashSet<int>();

                    foreach (var process in currentProcesses)
                    {
                        try
                        {
                            currentProcessIds.Add(process.Id);

                            // Check if process is already being tracked
                            if (_processesById.TryGetValue(process.Id, out var existingProcess))
                            {
                                // Update existing process info
                                UpdateProcessInfo(existingProcess, process);
                            }
                            else
                            {
                                // Add new process
                                var processInfo = CreateProcessInfo(process);
                                AddProcess(processInfo);

                                // Raise event for new process
                                ProcessStarted?.Invoke(this, new ProcessEventArgs(processInfo));

                                // Check if suspicious
                                if (processInfo.IsSuspicious)
                                {
                                    SuspiciousProcessDetected?.Invoke(this, new ProcessEventArgs(processInfo));
                                }
                            }
                        }
                        catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
                        {
                            // Process may have terminated while we were examining it
                            LogWarning($"Error processing process ID {process.Id}: {ex.Message}");
                        }
                        finally
                        {
                            // Ensure process is disposed
                            if (process != null && !_processesById.ContainsKey(process.Id))
                            {
                                process.Dispose();
                            }
                        }
                    }

                    // Find terminated processes
                    var terminatedProcessIds = _processesById.Keys.Where(id => !currentProcessIds.Contains(id)).ToList();
                    foreach (var id in terminatedProcessIds)
                    {
                        var processInfo = _processesById[id];
                        RemoveProcess(processInfo);

                        // Raise event for terminated process
                        ProcessTerminated?.Invoke(this, new ProcessEventArgs(processInfo));
                    }

                    // Update statistics
                    OnPropertyChanged(nameof(UnknownProcessCount));
                    OnPropertyChanged(nameof(SuspiciousProcessCount));
                }
            }
            catch (Exception ex)
            {
                LogError($"Error refreshing processes: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds a process to the whitelist
        /// </summary>
        public void AddToWhitelist(string processName)
        {
            if (!string.IsNullOrWhiteSpace(processName))
            {
                _whitelistedProcesses.Add(processName);
                LogInfo($"Added process to whitelist: {processName}");

                // Update existing processes
                foreach (var process in _processes.Where(p => string.Equals(p.Name, processName, StringComparison.OrdinalIgnoreCase)))
                {
                    process.IsWhitelisted = true;
                    process.IsUnknown = false;
                }
            }
        }

        /// <summary>
        /// Removes a process from the whitelist
        /// </summary>
        public void RemoveFromWhitelist(string processName)
        {
            if (!string.IsNullOrWhiteSpace(processName) && _whitelistedProcesses.Contains(processName))
            {
                _whitelistedProcesses.Remove(processName);
                LogInfo($"Removed process from whitelist: {processName}");

                // Update existing processes
                foreach (var process in _processes.Where(p => string.Equals(p.Name, processName, StringComparison.OrdinalIgnoreCase)))
                {
                    process.IsWhitelisted = false;
                    process.IsUnknown = !IsKnownSystemProcess(processName);
                }
            }
        }

        /// <summary>
        /// Calculates the MD5 hash of a file
        /// </summary>
        public static string CalculateFileHash(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return string.Empty;
                }

                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // File may be locked or access denied
                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the command line for a process
        /// </summary>
        public static string GetProcessCommandLine(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                using (var results = searcher.Get())
                {
                    foreach (var obj in results)
                    {
                        var commandLine = obj["CommandLine"];
                        if (commandLine != null)
                        {
                            return commandLine.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // WMI query may fail for various reasons
                LogWarning($"Error getting command line for process {processId}: {ex.Message}");
            }

            return string.Empty;
        }

        /// <summary>
        /// Gets the parent process ID for a process
        /// </summary>
        public static int GetParentProcessId(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                using (var results = searcher.Get())
                {
                    foreach (var obj in results)
                    {
                        return Convert.ToInt32(obj["ParentProcessId"]);
                    }
                }
            }
            catch (Exception ex)
            {
                // WMI query may fail for various reasons
                LogWarning($"Error getting parent process ID for process {processId}: {ex.Message}");
            }

            return 0;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the list of known system processes
        /// </summary>
        private void InitializeKnownProcesses()
        {
            // Common Windows system processes
            var knownProcesses = new[]
            {
                "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
                "winlogon", "explorer", "dwm", "taskhost", "taskhostw", "sihost",
                "runtimebroker", "shellexperiencehost", "applicationframehost",
                "searchui", "searchapp", "cortana", "backgroundtaskhost", "ctfmon",
                "conhost", "dllhost", "fontdrvhost", "registry", "devenv", "msbuild",
                "wmiprvse", "spoolsv", "searchindexer", "searchprotocolhost", "searchfilterhost"
            };

            foreach (var process in knownProcesses)
            {
                _knownSystemProcesses.Add(process);
            }
        }

        /// <summary>
        /// Creates a new ProcessInfo object from a Process
        /// </summary>
        private ProcessInfo CreateProcessInfo(Process process)
        {
            var processInfo = new ProcessInfo
            {
                Id = process.Id,
                Name = process.ProcessName,
                StartTime = GetProcessStartTime(process),
                IsResponding = process.Responding
            };

            try
            {
                processInfo.Path = process.MainModule?.FileName ?? string.Empty;
                processInfo.CommandLine = GetProcessCommandLine(process.Id);
                processInfo.ParentProcessId = GetParentProcessId(process.Id);

                // Calculate file hash if path is available
                if (!string.IsNullOrEmpty(processInfo.Path) && File.Exists(processInfo.Path))
                {
                    processInfo.FileHash = CalculateFileHash(processInfo.Path);
                }

                // Check if process is a known system process
                processInfo.IsUnknown = !IsKnownSystemProcess(processInfo.Name) && !IsWhitelisted(processInfo.Name);

                // Check if PowerShell with encoded command
                if (IsPowerShellWithEncodedCommand(processInfo.CommandLine))
                {
                    processInfo.IsSuspicious = true;
                    processInfo.SuspiciousReason = "PowerShell with encoded command";
                }

                // Get memory and CPU usage
                UpdateProcessUsage(processInfo, process);
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
            {
                // Process may have terminated or access denied
                processInfo.Path = "Access Denied";
                LogWarning($"Error accessing process {process.Id}: {ex.Message}");
            }

            return processInfo;
        }

        /// <summary>
        /// Updates an existing ProcessInfo object with current information
        /// </summary>
        private void UpdateProcessInfo(ProcessInfo processInfo, Process process)
        {
            try
            {
                // Update basic properties
                processInfo.IsResponding = process.Responding;

                // Update memory and CPU usage
                UpdateProcessUsage(processInfo, process);

                // Check for suspicious behavior
                CheckForSuspiciousBehavior(processInfo);
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
            {
                // Process may have terminated or access denied
                LogWarning($"Error updating process {process.Id}: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates memory and CPU usage for a process
        /// </summary>
        private void UpdateProcessUsage(ProcessInfo processInfo, Process process)
        {
            try
            {
                // Update memory usage
                processInfo.MemoryUsageMB = process.WorkingSet64 / 1024.0 / 1024.0;

                // Update CPU usage (requires multiple measurements)
                var startTime = DateTime.UtcNow;
                var startCpuUsage = process.TotalProcessorTime;

                // We'll update this on the next refresh cycle
                if (processInfo.LastCpuCheck != DateTime.MinValue)
                {
                    var endTime = startTime;
                    var endCpuUsage = startCpuUsage;

                    var cpuUsedMs = (endCpuUsage - processInfo.LastCpuTime).TotalMilliseconds;
                    var totalMsPassed = (endTime - processInfo.LastCpuCheck).TotalMilliseconds;
                    var cpuUsageTotal = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed);

                    processInfo.CpuUsagePercent = Math.Min(100, cpuUsageTotal * 100);

                    // Check for high CPU usage
                    if (processInfo.CpuUsagePercent > 80 && !processInfo.IsHighCpu)
                    {
                        processInfo.IsHighCpu = true;
                        processInfo.IsSuspicious = true;
                        processInfo.SuspiciousReason = "High CPU usage";
                    }
                    else if (processInfo.CpuUsagePercent < 70 && processInfo.IsHighCpu)
                    {
                        processInfo.IsHighCpu = false;
                        // Only remove suspicious flag if it was set for high CPU
                        if (processInfo.SuspiciousReason == "High CPU usage")
                        {
                            processInfo.IsSuspicious = false;
                            processInfo.SuspiciousReason = string.Empty;
                        }
                    }
                }

                // Store current values for next calculation
                processInfo.LastCpuTime = startCpuUsage;
                processInfo.LastCpuCheck = startTime;

                // Check for high memory usage (> 1GB)
                if (processInfo.MemoryUsageMB > 1024 && !processInfo.IsHighMemory)
                {
                    processInfo.IsHighMemory = true;
                    // Don't mark as suspicious just for high memory
                }
                else if (processInfo.MemoryUsageMB < 900 && processInfo.IsHighMemory)
                {
                    processInfo.IsHighMemory = false;
                }
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
            {
                // Process may have terminated or access denied
                LogWarning($"Error updating process usage {process.Id}: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks for suspicious behavior in a process
        /// </summary>
        private void CheckForSuspiciousBehavior(ProcessInfo processInfo)
        {
            // Already marked as suspicious
            if (processInfo.IsSuspicious)
            {
                return;
            }

            // Check for suspicious process names (common malware names)
            if (IsSuspiciousProcessName(processInfo.Name))
            {
                processInfo.IsSuspicious = true;
                processInfo.SuspiciousReason = "Suspicious process name";
                return;
            }

            // Check for suspicious paths
            if (IsSuspiciousPath(processInfo.Path))
            {
                processInfo.IsSuspicious = true;
                processInfo.SuspiciousReason = "Suspicious file location";
                return;
            }

            // Check for PowerShell with encoded commands
            if (IsPowerShellWithEncodedCommand(processInfo.CommandLine))
            {
                processInfo.IsSuspicious = true;
                processInfo.SuspiciousReason = "PowerShell with encoded command";
                return;
            }
        }

        /// <summary>
        /// Adds a process to the collection
        /// </summary>
        private void AddProcess(ProcessInfo processInfo)
        {
            if (!_processesById.ContainsKey(processInfo.Id))
            {
                _processesById.Add(processInfo.Id, processInfo);

                // Add to observable collection on UI thread
                App.Current.Dispatcher.Invoke(() =>
                {
                    _processes.Add(processInfo);
                });
            }
        }

        /// <summary>
        /// Removes a process from the collection
        /// </summary>
        private void RemoveProcess(ProcessInfo processInfo)
        {
            if (_processesById.ContainsKey(processInfo.Id))
            {
                _processesById.Remove(processInfo.Id);

                // Remove from observable collection on UI thread
                App.Current.Dispatcher.Invoke(() =>
                {
                    _processes.Remove(processInfo);
                });
            }
        }

        /// <summary>
        /// Gets the start time of a process
        /// </summary>
        private DateTime GetProcessStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch (Exception)
            {
                // Access denied or process has exited
                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// Checks if a process is a known system process
        /// </summary>
        private bool IsKnownSystemProcess(string processName)
        {
            return _knownSystemProcesses.Contains(processName);
        }

        /// <summary>
        /// Checks if a process is whitelisted
        /// </summary>
        private bool IsWhitelisted(string processName)
        {
            return _whitelistedProcesses.Contains(processName);
        }

        /// <summary>
        /// Checks if a process name is suspicious
        /// </summary>
        private bool IsSuspiciousProcessName(string processName)
        {
            // Common suspicious process names
            var suspiciousNames = new[]
            {
                "cryptominer", "miner", "xmrig", "xmr-stak", "nsclient", "psexec",
                "mimikatz", "cain", "netcat", "nc", "rar", "nmap", "keylogger",
                "hack", "crack", "steal", "dump", "inject", "rat", "trojan",
                "backdoor", "rootkit", "spyware", "adware", "malware"
            };

            return suspiciousNames.Any(name => processName.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>
        /// Checks if a process path is suspicious
        /// </summary>
        private bool IsSuspiciousPath(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            // Check for temp directories
            var tempPath = Path.GetTempPath();
            if (path.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Check for unusual directories
            var suspiciousPaths = new[]
            {
                "\\recycle", "\\temp\\", "\\windows\\temp", "\\programdata\\temp",
                "\\users\\public\\", "\\users\\default\\", "\\users\\all users\\"
            };

            return suspiciousPaths.Any(p => path.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>
        /// Checks if a command line is PowerShell with encoded command
        /// </summary>
        private bool IsPowerShellWithEncodedCommand(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
            {
                return false;
            }

            // Check for PowerShell with encoded command
            return (commandLine.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   commandLine.IndexOf("pwsh", StringComparison.OrdinalIgnoreCase) >= 0) &&
                   (commandLine.IndexOf("-e ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    commandLine.IndexOf("-enc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    commandLine.IndexOf("-encoded", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    commandLine.IndexOf("-encodedcommand", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [ProcessMonitor] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private static void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [ProcessMonitor] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [ProcessMonitor] {message}");
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

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    StopMonitoring();
                    _refreshTimer?.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }

    /// <summary>
    /// Represents information about a process
    /// </summary>
    public class ProcessInfo : INotifyPropertyChanged
    {
        private int _id;
        private string _name;
        private string _path;
        private string _commandLine;
        private int _parentProcessId;
        private DateTime _startTime;
        private bool _isResponding;
        private double _memoryUsageMB;
        private double _cpuUsagePercent;
        private bool _isUnknown;
        private bool _isSuspicious;
        private bool _isWhitelisted;
        private bool _isHighCpu;
        private bool _isHighMemory;
        private string _suspiciousReason;
        private string _fileHash;

        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int Id
        {
            get { return _id; }
            set
            {
                if (_id != value)
                {
                    _id = value;
                    OnPropertyChanged(nameof(Id));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string Name
        {
            get { return _name; }
            set
            {
                if (_name != value)
                {
                    _name = value;
                    OnPropertyChanged(nameof(Name));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process file path
        /// </summary>
        public string Path
        {
            get { return _path; }
            set
            {
                if (_path != value)
                {
                    _path = value;
                    OnPropertyChanged(nameof(Path));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process command line
        /// </summary>
        public string CommandLine
        {
            get { return _commandLine; }
            set
            {
                if (_commandLine != value)
                {
                    _commandLine = value;
                    OnPropertyChanged(nameof(CommandLine));
                }
            }
        }

        /// <summary>
        /// Gets or sets the parent process ID
        /// </summary>
        public int ParentProcessId
        {
            get { return _parentProcessId; }
            set
            {
                if (_parentProcessId != value)
                {
                    _parentProcessId = value;
                    OnPropertyChanged(nameof(ParentProcessId));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process start time
        /// </summary>
        public DateTime StartTime
        {
            get { return _startTime; }
            set
            {
                if (_startTime != value)
                {
                    _startTime = value;
                    OnPropertyChanged(nameof(StartTime));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process is responding
        /// </summary>
        public bool IsResponding
        {
            get { return _isResponding; }
            set
            {
                if (_isResponding != value)
                {
                    _isResponding = value;
                    OnPropertyChanged(nameof(IsResponding));
                }
            }
        }

        /// <summary>
        /// Gets or sets the memory usage in MB
        /// </summary>
        public double MemoryUsageMB
        {
            get { return _memoryUsageMB; }
            set
            {
                if (Math.Abs(_memoryUsageMB - value) > 0.1)
                {
                    _memoryUsageMB = value;
                    OnPropertyChanged(nameof(MemoryUsageMB));
                }
            }
        }

        /// <summary>
        /// Gets or sets the CPU usage percentage
        /// </summary>
        public double CpuUsagePercent
        {
            get { return _cpuUsagePercent; }
            set
            {
                if (Math.Abs(_cpuUsagePercent - value) > 0.1)
                {
                    _cpuUsagePercent = value;
                    OnPropertyChanged(nameof(CpuUsagePercent));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process is unknown
        /// </summary>
        public bool IsUnknown
        {
            get { return _isUnknown; }
            set
            {
                if (_isUnknown != value)
                {
                    _isUnknown = value;
                    OnPropertyChanged(nameof(IsUnknown));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process is suspicious
        /// </summary>
        public bool IsSuspicious
        {
            get { return _isSuspicious; }
            set
            {
                if (_isSuspicious != value)
                {
                    _isSuspicious = value;
                    OnPropertyChanged(nameof(IsSuspicious));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process is whitelisted
        /// </summary>
        public bool IsWhitelisted
        {
            get { return _isWhitelisted; }
            set
            {
                if (_isWhitelisted != value)
                {
                    _isWhitelisted = value;
                    OnPropertyChanged(nameof(IsWhitelisted));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process has high CPU usage
        /// </summary>
        public bool IsHighCpu
        {
            get { return _isHighCpu; }
            set
            {
                if (_isHighCpu != value)
                {
                    _isHighCpu = value;
                    OnPropertyChanged(nameof(IsHighCpu));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether the process has high memory usage
        /// </summary>
        public bool IsHighMemory
        {
            get { return _isHighMemory; }
            set
            {
                if (_isHighMemory != value)
                {
                    _isHighMemory = value;
                    OnPropertyChanged(nameof(IsHighMemory));
                }
            }
        }

        /// <summary>
        /// Gets or sets the reason why the process is suspicious
        /// </summary>
        public string SuspiciousReason
        {
            get { return _suspiciousReason; }
            set
            {
                if (_suspiciousReason != value)
                {
                    _suspiciousReason = value;
                    OnPropertyChanged(nameof(SuspiciousReason));
                }
            }
        }

        /// <summary>
        /// Gets or sets the file hash
        /// </summary>
        public string FileHash
        {
            get { return _fileHash; }
            set
            {
                if (_fileHash != value)
                {
                    _fileHash = value;
                    OnPropertyChanged(nameof(FileHash));
                }
            }
        }

        /// <summary>
        /// Gets the formatted start time
        /// </summary>
        public string StartTimeFormatted => StartTime != DateTime.MinValue ? StartTime.ToString("yyyy-MM-dd HH:mm:ss") : "Unknown";

        /// <summary>
        /// Gets the formatted memory usage
        /// </summary>
        public string MemoryUsageFormatted => $"{MemoryUsageMB:F2} MB";

        /// <summary>
        /// Gets the formatted CPU usage
        /// </summary>
        public string CpuUsageFormatted => $"{CpuUsagePercent:F1}%";

        // For CPU usage calculation
        internal DateTime LastCpuCheck { get; set; } = DateTime.MinValue;
        internal TimeSpan LastCpuTime { get; set; } = TimeSpan.Zero;

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// Event arguments for process events
    /// </summary>
    public class ProcessEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the process information
        /// </summary>
        public ProcessInfo ProcessInfo { get; }

        /// <summary>
        /// Initializes a new instance of the ProcessEventArgs class
        /// </summary>
        public ProcessEventArgs(ProcessInfo processInfo)
        {
            ProcessInfo = processInfo;
        }
    }
}