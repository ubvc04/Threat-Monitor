using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace WinSecMonitor.Modules.Processes
{
    /// <summary>
    /// Manages process monitoring and coordinates between different monitoring components
    /// </summary>
    public class ProcessMonitoringManager : INotifyPropertyChanged, IDisposable
    {
        #region Private Fields

        private readonly ProcessMonitor _processMonitor;
        private readonly MalwareDetector _malwareDetector;
        private readonly ProcessBehaviorAnalyzer _behaviorAnalyzer;
        private readonly PowerShellCommandAnalyzer _powerShellAnalyzer;
        private readonly ObservableCollection<ProcessAlert> _alerts;
        private readonly object _lockObject = new object();
        private bool _disposedValue;
        private int _maxAlerts = 100;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the process monitor
        /// </summary>
        public ProcessMonitor ProcessMonitor => _processMonitor;

        /// <summary>
        /// Gets the malware detector
        /// </summary>
        public MalwareDetector MalwareDetector => _malwareDetector;

        /// <summary>
        /// Gets the process behavior analyzer
        /// </summary>
        public ProcessBehaviorAnalyzer BehaviorAnalyzer => _behaviorAnalyzer;

        /// <summary>
        /// Gets the PowerShell command analyzer
        /// </summary>
        public PowerShellCommandAnalyzer PowerShellAnalyzer => _powerShellAnalyzer;

        /// <summary>
        /// Gets the collection of process alerts
        /// </summary>
        public ObservableCollection<ProcessAlert> Alerts => _alerts;

        /// <summary>
        /// Gets or sets the maximum number of alerts to keep
        /// </summary>
        public int MaxAlerts
        {
            get { return _maxAlerts; }
            set
            {
                if (_maxAlerts != value && value > 0)
                {
                    _maxAlerts = value;
                    OnPropertyChanged(nameof(MaxAlerts));

                    // Trim alerts if needed
                    TrimAlerts();
                }
            }
        }

        /// <summary>
        /// Gets the number of unknown processes
        /// </summary>
        public int UnknownProcessCount => _processMonitor.UnknownProcessCount;

        /// <summary>
        /// Gets the number of suspicious processes
        /// </summary>
        public int SuspiciousProcessCount => _processMonitor.SuspiciousProcessCount;

        /// <summary>
        /// Gets the number of alerts
        /// </summary>
        public int AlertCount => _alerts.Count;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the ProcessMonitoringManager class
        /// </summary>
        /// <param name="virustotalApiKey">Optional VirusTotal API key for online hash checking</param>
        public ProcessMonitoringManager(string virustotalApiKey = null)
        {
            _processMonitor = new ProcessMonitor();
            _malwareDetector = new MalwareDetector(virustotalApiKey);
            _behaviorAnalyzer = new ProcessBehaviorAnalyzer();
            _powerShellAnalyzer = new PowerShellCommandAnalyzer();
            _alerts = new ObservableCollection<ProcessAlert>();

            // Subscribe to process monitor events
            _processMonitor.ProcessStarted += ProcessMonitor_ProcessStarted;
            _processMonitor.ProcessTerminated += ProcessMonitor_ProcessTerminated;
            _processMonitor.SuspiciousProcessDetected += ProcessMonitor_SuspiciousProcessDetected;

            LogInfo("ProcessMonitoringManager initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring processes
        /// </summary>
        public void StartMonitoring()
        {
            _processMonitor.StartMonitoring();
            LogInfo("Process monitoring started");
        }

        /// <summary>
        /// Stops monitoring processes
        /// </summary>
        public void StopMonitoring()
        {
            _processMonitor.StopMonitoring();
            LogInfo("Process monitoring stopped");
        }

        /// <summary>
        /// Refreshes the process list
        /// </summary>
        public void RefreshProcesses()
        {
            _processMonitor.RefreshProcesses(null);
        }

        /// <summary>
        /// Adds a process to the whitelist
        /// </summary>
        public void AddToWhitelist(string processName)
        {
            _processMonitor.AddToWhitelist(processName);
        }

        /// <summary>
        /// Removes a process from the whitelist
        /// </summary>
        public void RemoveFromWhitelist(string processName)
        {
            _processMonitor.RemoveFromWhitelist(processName);
        }

        /// <summary>
        /// Adds a malware hash to the detector
        /// </summary>
        public void AddMalwareHash(string hash)
        {
            _malwareDetector.AddMalwareHash(hash);
        }

        /// <summary>
        /// Loads malware hashes from a file
        /// </summary>
        public int LoadMalwareHashesFromFile(string filePath)
        {
            return _malwareDetector.LoadHashesFromFile(filePath);
        }

        /// <summary>
        /// Saves malware hashes to a file
        /// </summary>
        public bool SaveMalwareHashesToFile(string filePath)
        {
            return _malwareDetector.SaveHashesToFile(filePath);
        }

        /// <summary>
        /// Clears all alerts
        /// </summary>
        public void ClearAlerts()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _alerts.Clear();
                OnPropertyChanged(nameof(AlertCount));
            });

            LogInfo("Alerts cleared");
        }

        /// <summary>
        /// Exports alerts to a CSV file
        /// </summary>
        public bool ExportAlertsToCsv(string filePath)
        {
            try
            {
                var lines = new List<string>
                {
                    "Timestamp,ProcessId,ProcessName,AlertType,Severity,Description"
                };

                foreach (var alert in _alerts)
                {
                    lines.Add($"{alert.Timestamp:yyyy-MM-dd HH:mm:ss},{alert.ProcessId},{alert.ProcessName},{alert.AlertType},{alert.Severity},{alert.Description.Replace(",", ";")}");
                }

                File.WriteAllLines(filePath, lines);
                LogInfo($"Exported {_alerts.Count} alerts to {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Error exporting alerts to CSV: {ex.Message}");
                return false;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Handles the ProcessStarted event
        /// </summary>
        private void ProcessMonitor_ProcessStarted(object sender, ProcessEventArgs e)
        {
            try
            {
                var processInfo = e.ProcessInfo;

                // Record process start for behavior analysis
                if (processInfo.ParentProcessId > 0)
                {
                    _behaviorAnalyzer.RecordProcessStart(processInfo.Name, processInfo.ParentProcessId, GetParentProcessName(processInfo.ParentProcessId));
                }

                // Check for malware hash
                if (!string.IsNullOrEmpty(processInfo.FileHash) && _malwareDetector.IsKnownMalwareHash(processInfo.FileHash))
                {
                    processInfo.IsSuspicious = true;
                    processInfo.SuspiciousReason = "Matches known malware hash";

                    AddAlert(new ProcessAlert
                    {
                        Timestamp = DateTime.Now,
                        ProcessId = processInfo.Id,
                        ProcessName = processInfo.Name,
                        AlertType = "Malware Hash Match",
                        Severity = AlertSeverity.High,
                        Description = $"Process {processInfo.Name} (ID: {processInfo.Id}) matches a known malware hash: {processInfo.FileHash}"
                    });
                }

                // Check for PowerShell with encoded commands
                if (!string.IsNullOrEmpty(processInfo.CommandLine) && 
                    (processInfo.CommandLine.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     processInfo.CommandLine.IndexOf("pwsh", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    var analysisResult = _powerShellAnalyzer.AnalyzeCommand(processInfo.CommandLine);
                    if (analysisResult.IsEncodedCommand && analysisResult.IsSuspicious)
                    {
                        processInfo.IsSuspicious = true;
                        processInfo.SuspiciousReason = $"Suspicious PowerShell encoded command: {analysisResult.SuspiciousReason}";

                        AddAlert(new ProcessAlert
                        {
                            Timestamp = DateTime.Now,
                            ProcessId = processInfo.Id,
                            ProcessName = processInfo.Name,
                            AlertType = "Encoded PowerShell",
                            Severity = AlertSeverity.High,
                            Description = $"Process {processInfo.Name} (ID: {processInfo.Id}) contains suspicious encoded PowerShell command: {analysisResult.SuspiciousReason}"
                        });
                    }
                }

                // Analyze process behavior
                var behaviorResult = _behaviorAnalyzer.AnalyzeProcess(processInfo);
                if (behaviorResult != null && behaviorResult.IsUnusual)
                {
                    processInfo.IsSuspicious = true;
                    processInfo.SuspiciousReason = $"Unusual behavior: {string.Join(", ", behaviorResult.UnusualBehaviors)}";

                    AddAlert(new ProcessAlert
                    {
                        Timestamp = DateTime.Now,
                        ProcessId = processInfo.Id,
                        ProcessName = processInfo.Name,
                        AlertType = "Unusual Behavior",
                        Severity = AlertSeverity.Medium,
                        Description = $"Process {processInfo.Name} (ID: {processInfo.Id}) exhibits unusual behavior: {string.Join(", ", behaviorResult.UnusualBehaviors)}"
                    });
                }

                // Check if this is an unknown process
                if (processInfo.IsUnknown && !processInfo.IsSuspicious)
                {
                    AddAlert(new ProcessAlert
                    {
                        Timestamp = DateTime.Now,
                        ProcessId = processInfo.Id,
                        ProcessName = processInfo.Name,
                        AlertType = "Unknown Process",
                        Severity = AlertSeverity.Low,
                        Description = $"Unknown process started: {processInfo.Name} (ID: {processInfo.Id}) at {processInfo.Path}"
                    });
                }
            }
            catch (Exception ex)
            {
                LogError($"Error handling process started event: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the ProcessTerminated event
        /// </summary>
        private void ProcessMonitor_ProcessTerminated(object sender, ProcessEventArgs e)
        {
            try
            {
                // Clean up behavior data for terminated process
                _behaviorAnalyzer.ClearProcessData(e.ProcessInfo.Id);
            }
            catch (Exception ex)
            {
                LogError($"Error handling process terminated event: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the SuspiciousProcessDetected event
        /// </summary>
        private void ProcessMonitor_SuspiciousProcessDetected(object sender, ProcessEventArgs e)
        {
            try
            {
                var processInfo = e.ProcessInfo;

                // Add alert for suspicious process
                AddAlert(new ProcessAlert
                {
                    Timestamp = DateTime.Now,
                    ProcessId = processInfo.Id,
                    ProcessName = processInfo.Name,
                    AlertType = "Suspicious Process",
                    Severity = AlertSeverity.Medium,
                    Description = $"Suspicious process detected: {processInfo.Name} (ID: {processInfo.Id}) - {processInfo.SuspiciousReason}"
                });
            }
            catch (Exception ex)
            {
                LogError($"Error handling suspicious process detected event: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the name of a parent process
        /// </summary>
        private string GetParentProcessName(int parentProcessId)
        {
            foreach (var process in _processMonitor.Processes)
            {
                if (process.Id == parentProcessId)
                {
                    return process.Name;
                }
            }

            return "Unknown";
        }

        /// <summary>
        /// Adds an alert to the collection
        /// </summary>
        private void AddAlert(ProcessAlert alert)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _alerts.Add(alert);
                OnPropertyChanged(nameof(AlertCount));

                // Trim alerts if needed
                TrimAlerts();
            });

            LogInfo($"Alert added: {alert.AlertType} - {alert.Description}");
        }

        /// <summary>
        /// Trims the alerts collection to the maximum number of alerts
        /// </summary>
        private void TrimAlerts()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                while (_alerts.Count > _maxAlerts)
                {
                    _alerts.RemoveAt(0);
                }
            });
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [ProcessMonitoringManager] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [ProcessMonitoringManager] {message}");
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
                    _processMonitor.ProcessStarted -= ProcessMonitor_ProcessStarted;
                    _processMonitor.ProcessTerminated -= ProcessMonitor_ProcessTerminated;
                    _processMonitor.SuspiciousProcessDetected -= ProcessMonitor_SuspiciousProcessDetected;
                    _processMonitor.Dispose();
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
    /// Represents an alert for a process
    /// </summary>
    public class ProcessAlert
    {
        /// <summary>
        /// Gets or sets the timestamp of the alert
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets the alert type
        /// </summary>
        public string AlertType { get; set; }

        /// <summary>
        /// Gets or sets the alert severity
        /// </summary>
        public AlertSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the alert description
        /// </summary>
        public string Description { get; set; }
    }

    /// <summary>
    /// Represents the severity of an alert
    /// </summary>
    public enum AlertSeverity
    {
        /// <summary>
        /// Low severity
        /// </summary>
        Low,

        /// <summary>
        /// Medium severity
        /// </summary>
        Medium,

        /// <summary>
        /// High severity
        /// </summary>
        High
    }
}