using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Network
{
    /// <summary>
    /// Manages network monitoring components and coordinates their activities
    /// </summary>
    public class NetworkMonitoringManager : INotifyPropertyChanged, IDisposable
    {
        #region Private Fields

        private readonly NetworkMonitor _networkMonitor;
        private readonly BlacklistChecker _blacklistChecker;
        private readonly NetworkTrafficAnalyzer _trafficAnalyzer;
        private readonly ObservableCollection<NetworkAlert> _alerts;
        private int _maxAlerts = 1000;
        private bool _isMonitoring;
        private int _refreshInterval = 5;
        private bool _disposedValue;

        #endregion

        #region Events

        /// <summary>
        /// Occurs when a new alert is added
        /// </summary>
        public event EventHandler<NetworkAlertEventArgs> AlertAdded;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the network monitor
        /// </summary>
        public NetworkMonitor NetworkMonitor => _networkMonitor;

        /// <summary>
        /// Gets the blacklist checker
        /// </summary>
        public BlacklistChecker BlacklistChecker => _blacklistChecker;

        /// <summary>
        /// Gets the traffic analyzer
        /// </summary>
        public NetworkTrafficAnalyzer TrafficAnalyzer => _trafficAnalyzer;

        /// <summary>
        /// Gets the collection of alerts
        /// </summary>
        public ObservableCollection<NetworkAlert> Alerts => _alerts;

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

                    // Trim alerts if necessary
                    TrimAlerts();
                }
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the manager is currently monitoring
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

        /// <summary>
        /// Gets or sets the refresh interval in seconds
        /// </summary>
        public int RefreshInterval
        {
            get { return _refreshInterval; }
            set
            {
                if (_refreshInterval != value && value > 0)
                {
                    _refreshInterval = value;
                    OnPropertyChanged(nameof(RefreshInterval));

                    // Update the network monitor's refresh interval
                    _networkMonitor.RefreshInterval = value;
                }
            }
        }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the NetworkMonitoringManager class
        /// </summary>
        public NetworkMonitoringManager()
        {
            _networkMonitor = new NetworkMonitor();
            _blacklistChecker = new BlacklistChecker();
            _trafficAnalyzer = new NetworkTrafficAnalyzer();
            _alerts = new ObservableCollection<NetworkAlert>();

            // Subscribe to events
            _networkMonitor.ConnectionAdded += NetworkMonitor_ConnectionAdded;
            _networkMonitor.SuspiciousConnectionDetected += NetworkMonitor_SuspiciousConnectionDetected;

            LogInfo("NetworkMonitoringManager initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring network activity
        /// </summary>
        public void StartMonitoring()
        {
            if (!_isMonitoring)
            {
                // Start the network monitor
                _networkMonitor.StartMonitoring();
                IsMonitoring = true;
                LogInfo("Network monitoring started");
            }
        }

        /// <summary>
        /// Stops monitoring network activity
        /// </summary>
        public void StopMonitoring()
        {
            if (_isMonitoring)
            {
                // Stop the network monitor
                _networkMonitor.StopMonitoring();
                IsMonitoring = false;
                LogInfo("Network monitoring stopped");
            }
        }

        /// <summary>
        /// Refreshes network connections
        /// </summary>
        public void RefreshConnections()
        {
            _networkMonitor.RefreshConnections(null);
        }

        /// <summary>
        /// Adds an IP address to the blacklist
        /// </summary>
        public void AddToBlacklist(string ipAddress)
        {
            _blacklistChecker.AddToBlacklist(ipAddress);
        }

        /// <summary>
        /// Removes an IP address from the blacklist
        /// </summary>
        public void RemoveFromBlacklist(string ipAddress)
        {
            _blacklistChecker.RemoveFromBlacklist(ipAddress);
        }

        /// <summary>
        /// Adds an IP address to the whitelist
        /// </summary>
        public void AddToWhitelist(string ipAddress)
        {
            _blacklistChecker.AddToWhitelist(ipAddress);
        }

        /// <summary>
        /// Removes an IP address from the whitelist
        /// </summary>
        public void RemoveFromWhitelist(string ipAddress)
        {
            _blacklistChecker.RemoveFromWhitelist(ipAddress);
        }

        /// <summary>
        /// Loads blacklisted IPs from a file
        /// </summary>
        public void LoadBlacklistFromFile(string filePath)
        {
            _blacklistChecker.LoadBlacklistFromFile(filePath);
        }

        /// <summary>
        /// Saves blacklisted IPs to a file
        /// </summary>
        public void SaveBlacklistToFile(string filePath)
        {
            _blacklistChecker.SaveBlacklistToFile(filePath);
        }

        /// <summary>
        /// Loads whitelisted IPs from a file
        /// </summary>
        public void LoadWhitelistFromFile(string filePath)
        {
            _blacklistChecker.LoadWhitelistFromFile(filePath);
        }

        /// <summary>
        /// Saves whitelisted IPs to a file
        /// </summary>
        public void SaveWhitelistToFile(string filePath)
        {
            _blacklistChecker.SaveWhitelistToFile(filePath);
        }

        /// <summary>
        /// Adds a known malicious domain
        /// </summary>
        public void AddMaliciousDomain(string domain)
        {
            _blacklistChecker.AddMaliciousDomain(domain);
        }

        /// <summary>
        /// Loads known malicious domains from a file
        /// </summary>
        public void LoadMaliciousDomainsFromFile(string filePath)
        {
            _blacklistChecker.LoadMaliciousDomainsFromFile(filePath);
        }

        /// <summary>
        /// Saves known malicious domains to a file
        /// </summary>
        public void SaveMaliciousDomainsToFile(string filePath)
        {
            _blacklistChecker.SaveMaliciousDomainsToFile(filePath);
        }

        /// <summary>
        /// Clears all alerts
        /// </summary>
        public void ClearAlerts()
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                _alerts.Clear();
            });
            LogInfo("Cleared all alerts");
        }

        /// <summary>
        /// Exports alerts to a CSV file
        /// </summary>
        public void ExportAlertsToCsv(string filePath)
        {
            try
            {
                // Create a StringBuilder to build the CSV content
                var csv = new StringBuilder();

                // Add the header row
                csv.AppendLine("Timestamp,Severity,Type,Description,IP Address,Port,Process Name,Process ID");

                // Add each alert as a row
                foreach (var alert in _alerts)
                {
                    csv.AppendLine($"{alert.Timestamp:yyyy-MM-dd HH:mm:ss},"
                        + $"{alert.Severity},"
                        + $"{alert.AlertType},"
                        + $"\"{alert.Description.Replace("\"", "\"\"")}\","
                        + $"{alert.IpAddress},"
                        + $"{alert.Port},"
                        + $"{alert.ProcessName},"
                        + $"{alert.ProcessId}");
                }

                // Write the CSV content to the file
                File.WriteAllText(filePath, csv.ToString());

                LogInfo($"Exported {_alerts.Count} alerts to {filePath}");
            }
            catch (Exception ex)
            {
                LogError($"Error exporting alerts to CSV: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Handles the ConnectionAdded event of the NetworkMonitor
        /// </summary>
        private async void NetworkMonitor_ConnectionAdded(object sender, NetworkConnectionEventArgs e)
        {
            try
            {
                // Check if the connection is blacklisted
                var blacklistResult = await _blacklistChecker.CheckIpAsync(e.Connection.RemoteAddress);
                if (blacklistResult.IsBlacklisted)
                {
                    // Add an alert for the blacklisted connection
                    AddAlert(new NetworkAlert
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.High,
                        AlertType = "Blacklisted IP",
                        Description = $"Connection to blacklisted IP: {e.Connection.RemoteAddress} ({blacklistResult.Reason})",
                        IpAddress = e.Connection.RemoteAddress,
                        Port = e.Connection.RemotePort,
                        ProcessName = e.Connection.ProcessName,
                        ProcessId = e.Connection.ProcessId
                    });

                    LogWarning($"Blacklisted IP detected: {e.Connection.RemoteAddress} ({blacklistResult.Reason})");
                    return;
                }

                // Analyze the connection for unusual traffic patterns
                var trafficResult = _trafficAnalyzer.AnalyzeConnection(e.Connection);
                if (trafficResult.IsUnusual)
                {
                    // Add an alert for the unusual traffic
                    AddAlert(new NetworkAlert
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.Medium,
                        AlertType = "Unusual Traffic",
                        Description = $"Unusual network traffic detected: {trafficResult.Reason}",
                        IpAddress = e.Connection.RemoteAddress,
                        Port = e.Connection.RemotePort,
                        ProcessName = e.Connection.ProcessName,
                        ProcessId = e.Connection.ProcessId
                    });

                    LogWarning($"Unusual traffic detected: {trafficResult.Reason}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error handling new connection: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the SuspiciousConnectionDetected event of the NetworkMonitor
        /// </summary>
        private void NetworkMonitor_SuspiciousConnectionDetected(object sender, NetworkConnectionEventArgs e)
        {
            try
            {
                // Add an alert for the suspicious connection
                AddAlert(new NetworkAlert
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.Medium,
                    AlertType = "Suspicious Connection",
                    Description = $"Suspicious connection detected: {e.Connection.RemoteAddress}:{e.Connection.RemotePort} ({e.Connection.SuspiciousReason})",
                    IpAddress = e.Connection.RemoteAddress,
                    Port = e.Connection.RemotePort,
                    ProcessName = e.Connection.ProcessName,
                    ProcessId = e.Connection.ProcessId
                });

                LogWarning($"Suspicious connection detected: {e.Connection.RemoteAddress}:{e.Connection.RemotePort} ({e.Connection.SuspiciousReason})");
            }
            catch (Exception ex)
            {
                LogError($"Error handling suspicious connection: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds an alert to the alerts collection
        /// </summary>
        private void AddAlert(NetworkAlert alert)
        {
            try
            {
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    // Add the alert to the collection
                    _alerts.Add(alert);

                    // Trim the alerts if necessary
                    TrimAlerts();

                    // Raise the AlertAdded event
                    AlertAdded?.Invoke(this, new NetworkAlertEventArgs(alert));
                });
            }
            catch (Exception ex)
            {
                LogError($"Error adding alert: {ex.Message}");
            }
        }

        /// <summary>
        /// Trims the alerts collection to the maximum number of alerts
        /// </summary>
        private void TrimAlerts()
        {
            try
            {
                // Remove oldest alerts if we have too many
                while (_alerts.Count > _maxAlerts)
                {
                    _alerts.RemoveAt(0);
                }
            }
            catch (Exception ex)
            {
                LogError($"Error trimming alerts: {ex.Message}");
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [NetworkMonitoringManager] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private static void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [NetworkMonitoringManager] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [NetworkMonitoringManager] {message}");
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
                    _networkMonitor.Dispose();
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
    /// Represents a network alert
    /// </summary>
    public class NetworkAlert : INotifyPropertyChanged
    {
        private DateTime _timestamp;
        private AlertSeverity _severity;
        private string _alertType;
        private string _description;
        private string _ipAddress;
        private int _port;
        private string _processName;
        private int _processId;

        /// <summary>
        /// Gets or sets the timestamp
        /// </summary>
        public DateTime Timestamp
        {
            get { return _timestamp; }
            set
            {
                if (_timestamp != value)
                {
                    _timestamp = value;
                    OnPropertyChanged(nameof(Timestamp));
                }
            }
        }

        /// <summary>
        /// Gets or sets the severity
        /// </summary>
        public AlertSeverity Severity
        {
            get { return _severity; }
            set
            {
                if (_severity != value)
                {
                    _severity = value;
                    OnPropertyChanged(nameof(Severity));
                }
            }
        }

        /// <summary>
        /// Gets or sets the alert type
        /// </summary>
        public string AlertType
        {
            get { return _alertType; }
            set
            {
                if (_alertType != value)
                {
                    _alertType = value;
                    OnPropertyChanged(nameof(AlertType));
                }
            }
        }

        /// <summary>
        /// Gets or sets the description
        /// </summary>
        public string Description
        {
            get { return _description; }
            set
            {
                if (_description != value)
                {
                    _description = value;
                    OnPropertyChanged(nameof(Description));
                }
            }
        }

        /// <summary>
        /// Gets or sets the IP address
        /// </summary>
        public string IpAddress
        {
            get { return _ipAddress; }
            set
            {
                if (_ipAddress != value)
                {
                    _ipAddress = value;
                    OnPropertyChanged(nameof(IpAddress));
                }
            }
        }

        /// <summary>
        /// Gets or sets the port
        /// </summary>
        public int Port
        {
            get { return _port; }
            set
            {
                if (_port != value)
                {
                    _port = value;
                    OnPropertyChanged(nameof(Port));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName
        {
            get { return _processName; }
            set
            {
                if (_processName != value)
                {
                    _processName = value;
                    OnPropertyChanged(nameof(ProcessName));
                }
            }
        }

        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId
        {
            get { return _processId; }
            set
            {
                if (_processId != value)
                {
                    _processId = value;
                    OnPropertyChanged(nameof(ProcessId));
                }
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
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
        High,

        /// <summary>
        /// Critical severity
        /// </summary>
        Critical
    }

    /// <summary>
    /// Event arguments for network alert events
    /// </summary>
    public class NetworkAlertEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the network alert
        /// </summary>
        public NetworkAlert Alert { get; }

        /// <summary>
        /// Initializes a new instance of the NetworkAlertEventArgs class
        /// </summary>
        public NetworkAlertEventArgs(NetworkAlert alert)
        {
            Alert = alert;
        }
    }
}