using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Network
{
    /// <summary>
    /// Monitors active network connections and provides information about them
    /// </summary>
    public class NetworkMonitor : INotifyPropertyChanged, IDisposable
    {
        #region Private Fields

        private readonly ObservableCollection<NetworkConnection> _connections;
        private readonly Dictionary<string, NetworkConnection> _connectionCache;
        private readonly object _lockObject = new object();
        private readonly Dictionary<int, string> _processNames;
        private Timer _monitorTimer;
        private bool _isMonitoring;
        private int _refreshInterval = 5;
        private int _totalConnections;
        private int _totalTcpConnections;
        private int _totalUdpConnections;
        private int _totalListeningPorts;
        private int _totalEstablishedConnections;
        private bool _disposedValue;

        #endregion

        #region Events

        /// <summary>
        /// Occurs when a new connection is detected
        /// </summary>
        public event EventHandler<NetworkConnectionEventArgs> ConnectionAdded;

        /// <summary>
        /// Occurs when a connection is removed
        /// </summary>
        public event EventHandler<NetworkConnectionEventArgs> ConnectionRemoved;

        /// <summary>
        /// Occurs when a suspicious connection is detected
        /// </summary>
        public event EventHandler<NetworkConnectionEventArgs> SuspiciousConnectionDetected;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the collection of active network connections
        /// </summary>
        public ObservableCollection<NetworkConnection> Connections => _connections;

        /// <summary>
        /// Gets or sets a value indicating whether the monitor is currently monitoring
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

                    // Update the timer if monitoring
                    if (_isMonitoring)
                    {
                        StopMonitoring();
                        StartMonitoring();
                    }
                }
            }
        }

        /// <summary>
        /// Gets the total number of connections
        /// </summary>
        public int TotalConnections
        {
            get { return _totalConnections; }
            private set
            {
                if (_totalConnections != value)
                {
                    _totalConnections = value;
                    OnPropertyChanged(nameof(TotalConnections));
                }
            }
        }

        /// <summary>
        /// Gets the total number of TCP connections
        /// </summary>
        public int TotalTcpConnections
        {
            get { return _totalTcpConnections; }
            private set
            {
                if (_totalTcpConnections != value)
                {
                    _totalTcpConnections = value;
                    OnPropertyChanged(nameof(TotalTcpConnections));
                }
            }
        }

        /// <summary>
        /// Gets the total number of UDP connections
        /// </summary>
        public int TotalUdpConnections
        {
            get { return _totalUdpConnections; }
            private set
            {
                if (_totalUdpConnections != value)
                {
                    _totalUdpConnections = value;
                    OnPropertyChanged(nameof(TotalUdpConnections));
                }
            }
        }

        /// <summary>
        /// Gets the total number of listening ports
        /// </summary>
        public int TotalListeningPorts
        {
            get { return _totalListeningPorts; }
            private set
            {
                if (_totalListeningPorts != value)
                {
                    _totalListeningPorts = value;
                    OnPropertyChanged(nameof(TotalListeningPorts));
                }
            }
        }

        /// <summary>
        /// Gets the total number of established connections
        /// </summary>
        public int TotalEstablishedConnections
        {
            get { return _totalEstablishedConnections; }
            private set
            {
                if (_totalEstablishedConnections != value)
                {
                    _totalEstablishedConnections = value;
                    OnPropertyChanged(nameof(TotalEstablishedConnections));
                }
            }
        }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the NetworkMonitor class
        /// </summary>
        public NetworkMonitor()
        {
            _connections = new ObservableCollection<NetworkConnection>();
            _connectionCache = new Dictionary<string, NetworkConnection>();
            _processNames = new Dictionary<int, string>();

            LogInfo("NetworkMonitor initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Starts monitoring network connections
        /// </summary>
        public void StartMonitoring()
        {
            if (!_isMonitoring)
            {
                // Create a timer to refresh connections periodically
                _monitorTimer = new Timer(RefreshConnections, null, 0, _refreshInterval * 1000);
                IsMonitoring = true;
                LogInfo("Network monitoring started");
            }
        }

        /// <summary>
        /// Stops monitoring network connections
        /// </summary>
        public void StopMonitoring()
        {
            if (_isMonitoring)
            {
                // Stop the timer
                _monitorTimer?.Dispose();
                _monitorTimer = null;
                IsMonitoring = false;
                LogInfo("Network monitoring stopped");
            }
        }

        /// <summary>
        /// Refreshes the network connections
        /// </summary>
        public void RefreshConnections(object state)
        {
            try
            {
                // Get all active TCP connections
                var tcpConnections = GetTcpConnections();

                // Get all active UDP connections
                var udpConnections = GetUdpConnections();

                // Combine the connections
                var allConnections = new List<NetworkConnection>();
                allConnections.AddRange(tcpConnections);
                allConnections.AddRange(udpConnections);

                // Update the connections collection
                UpdateConnections(allConnections);

                // Update statistics
                UpdateStatistics();

                LogInfo($"Refreshed connections: {allConnections.Count} total");
            }
            catch (Exception ex)
            {
                LogError($"Error refreshing connections: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the process name for a process ID
        /// </summary>
        public string GetProcessName(int processId)
        {
            try
            {
                // Check if we already have the process name cached
                if (_processNames.TryGetValue(processId, out string name))
                {
                    return name;
                }

                // Get the process name
                using (var process = Process.GetProcessById(processId))
                {
                    name = process.ProcessName;
                    _processNames[processId] = name;
                    return name;
                }
            }
            catch (Exception ex)
            {
                LogError($"Error getting process name for PID {processId}: {ex.Message}");
                return "Unknown";
            }
        }

        /// <summary>
        /// Resolves an IP address to a hostname
        /// </summary>
        public string ResolveHostname(string ipAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress) || ipAddress == "0.0.0.0" || ipAddress == "127.0.0.1" || ipAddress == "::1")
                {
                    return "localhost";
                }

                IPHostEntry hostEntry = Dns.GetHostEntry(ipAddress);
                return hostEntry.HostName;
            }
            catch
            {
                // If we can't resolve the hostname, just return the IP address
                return ipAddress;
            }
        }

        /// <summary>
        /// Gets the service name for a port number
        /// </summary>
        public string GetServiceName(int port, ProtocolType protocol)
        {
            // Common port mappings
            var commonPorts = new Dictionary<int, string>
            {
                { 20, "FTP Data" },
                { 21, "FTP Control" },
                { 22, "SSH" },
                { 23, "Telnet" },
                { 25, "SMTP" },
                { 53, "DNS" },
                { 80, "HTTP" },
                { 110, "POP3" },
                { 143, "IMAP" },
                { 443, "HTTPS" },
                { 465, "SMTPS" },
                { 587, "SMTP Submission" },
                { 993, "IMAPS" },
                { 995, "POP3S" },
                { 1433, "SQL Server" },
                { 3306, "MySQL" },
                { 3389, "RDP" },
                { 5432, "PostgreSQL" },
                { 8080, "HTTP Alternate" },
                { 8443, "HTTPS Alternate" }
            };

            if (commonPorts.TryGetValue(port, out string serviceName))
            {
                return serviceName;
            }

            return "Unknown";
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Gets all active TCP connections
        /// </summary>
        private List<NetworkConnection> GetTcpConnections()
        {
            var connections = new List<NetworkConnection>();

            try
            {
                // Get all active TCP connections
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] tcpConnections = properties.GetActiveTcpConnections();

                foreach (TcpConnectionInformation tcpConnection in tcpConnections)
                {
                    // Get the local endpoint
                    IPEndPoint localEndPoint = tcpConnection.LocalEndPoint;
                    string localAddress = localEndPoint.Address.ToString();
                    int localPort = localEndPoint.Port;

                    // Get the remote endpoint
                    IPEndPoint remoteEndPoint = tcpConnection.RemoteEndPoint;
                    string remoteAddress = remoteEndPoint.Address.ToString();
                    int remotePort = remoteEndPoint.Port;

                    // Get the connection state
                    TcpState state = tcpConnection.State;

                    // Create a new connection object
                    var connection = new NetworkConnection
                    {
                        Protocol = ProtocolType.Tcp,
                        LocalAddress = localAddress,
                        LocalPort = localPort,
                        RemoteAddress = remoteAddress,
                        RemotePort = remotePort,
                        State = state.ToString(),
                        ProcessId = GetProcessIdForTcpConnection(localAddress, localPort, remoteAddress, remotePort),
                        Timestamp = DateTime.Now
                    };

                    // Set the process name
                    if (connection.ProcessId > 0)
                    {
                        connection.ProcessName = GetProcessName(connection.ProcessId);
                    }

                    // Set the service name
                    connection.ServiceName = GetServiceName(connection.LocalPort, ProtocolType.Tcp);

                    // Add the connection to the list
                    connections.Add(connection);
                }
            }
            catch (Exception ex)
            {
                LogError($"Error getting TCP connections: {ex.Message}");
            }

            return connections;
        }

        /// <summary>
        /// Gets all active UDP connections
        /// </summary>
        private List<NetworkConnection> GetUdpConnections()
        {
            var connections = new List<NetworkConnection>();

            try
            {
                // Get all active UDP listeners
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                IPEndPoint[] udpListeners = properties.GetActiveUdpListeners();

                foreach (IPEndPoint udpListener in udpListeners)
                {
                    // Get the local endpoint
                    string localAddress = udpListener.Address.ToString();
                    int localPort = udpListener.Port;

                    // Create a new connection object
                    var connection = new NetworkConnection
                    {
                        Protocol = ProtocolType.Udp,
                        LocalAddress = localAddress,
                        LocalPort = localPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "Listening",
                        ProcessId = GetProcessIdForUdpListener(localAddress, localPort),
                        Timestamp = DateTime.Now
                    };

                    // Set the process name
                    if (connection.ProcessId > 0)
                    {
                        connection.ProcessName = GetProcessName(connection.ProcessId);
                    }

                    // Set the service name
                    connection.ServiceName = GetServiceName(connection.LocalPort, ProtocolType.Udp);

                    // Add the connection to the list
                    connections.Add(connection);
                }
            }
            catch (Exception ex)
            {
                LogError($"Error getting UDP connections: {ex.Message}");
            }

            return connections;
        }

        /// <summary>
        /// Gets the process ID for a TCP connection
        /// </summary>
        private int GetProcessIdForTcpConnection(string localAddress, int localPort, string remoteAddress, int remotePort)
        {
            try
            {
                // Use netstat to get the process ID
                // This is a workaround since .NET doesn't provide a direct way to get the process ID for a connection
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = "-ano",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse the output to find the process ID
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    if (line.Contains("TCP") && line.Contains($":{localPort}") && line.Contains($":{remotePort}"))
                    {
                        string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5)
                        {
                            if (int.TryParse(parts[4], out int processId))
                            {
                                return processId;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error getting process ID for TCP connection: {ex.Message}");
            }

            return 0;
        }

        /// <summary>
        /// Gets the process ID for a UDP listener
        /// </summary>
        private int GetProcessIdForUdpListener(string localAddress, int localPort)
        {
            try
            {
                // Use netstat to get the process ID
                // This is a workaround since .NET doesn't provide a direct way to get the process ID for a connection
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = "-ano",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse the output to find the process ID
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    if (line.Contains("UDP") && line.Contains($":{localPort}"))
                    {
                        string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 4)
                        {
                            if (int.TryParse(parts[3], out int processId))
                            {
                                return processId;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error getting process ID for UDP listener: {ex.Message}");
            }

            return 0;
        }

        /// <summary>
        /// Updates the connections collection
        /// </summary>
        private void UpdateConnections(List<NetworkConnection> newConnections)
        {
            lock (_lockObject)
            {
                try
                {
                    // Create a dictionary of current connections for faster lookup
                    var currentConnections = new Dictionary<string, NetworkConnection>();
                    foreach (var connection in _connections)
                    {
                        currentConnections[connection.ConnectionId] = connection;
                    }

                    // Create a dictionary of new connections for faster lookup
                    var newConnectionsDict = new Dictionary<string, NetworkConnection>();
                    foreach (var connection in newConnections)
                    {
                        newConnectionsDict[connection.ConnectionId] = connection;
                    }

                    // Find connections to add
                    var connectionsToAdd = newConnections.Where(c => !currentConnections.ContainsKey(c.ConnectionId)).ToList();

                    // Find connections to remove
                    var connectionsToRemove = _connections.Where(c => !newConnectionsDict.ContainsKey(c.ConnectionId)).ToList();

                    // Update the UI on the UI thread
                    System.Windows.Application.Current.Dispatcher.Invoke(() =>
                    {
                        // Remove old connections
                        foreach (var connection in connectionsToRemove)
                        {
                            _connections.Remove(connection);
                            _connectionCache.Remove(connection.ConnectionId);

                            // Raise the ConnectionRemoved event
                            ConnectionRemoved?.Invoke(this, new NetworkConnectionEventArgs(connection));
                        }

                        // Add new connections
                        foreach (var connection in connectionsToAdd)
                        {
                            _connections.Add(connection);
                            _connectionCache[connection.ConnectionId] = connection;

                            // Raise the ConnectionAdded event
                            ConnectionAdded?.Invoke(this, new NetworkConnectionEventArgs(connection));

                            // Check if the connection is suspicious
                            if (IsSuspiciousConnection(connection))
                            {
                                connection.IsSuspicious = true;
                                SuspiciousConnectionDetected?.Invoke(this, new NetworkConnectionEventArgs(connection));
                            }
                        }
                    });
                }
                catch (Exception ex)
                {
                    LogError($"Error updating connections: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Updates the statistics
        /// </summary>
        private void UpdateStatistics()
        {
            try
            {
                TotalConnections = _connections.Count;
                TotalTcpConnections = _connections.Count(c => c.Protocol == ProtocolType.Tcp);
                TotalUdpConnections = _connections.Count(c => c.Protocol == ProtocolType.Udp);
                TotalListeningPorts = _connections.Count(c => c.State == "LISTENING" || c.State == "Listening");
                TotalEstablishedConnections = _connections.Count(c => c.State == "ESTABLISHED" || c.State == "Established");
            }
            catch (Exception ex)
            {
                LogError($"Error updating statistics: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if a connection is suspicious
        /// </summary>
        private bool IsSuspiciousConnection(NetworkConnection connection)
        {
            // This is a placeholder for more sophisticated detection logic
            // In a real implementation, this would check against blacklists, known malicious ports, etc.
            return false;
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [NetworkMonitor] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [NetworkMonitor] {message}");
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
                    _monitorTimer?.Dispose();
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
    /// Represents a network connection
    /// </summary>
    public class NetworkConnection : INotifyPropertyChanged
    {
        private bool _isSuspicious;
        private string _suspiciousReason;

        /// <summary>
        /// Gets or sets the protocol
        /// </summary>
        public ProtocolType Protocol { get; set; }

        /// <summary>
        /// Gets or sets the local address
        /// </summary>
        public string LocalAddress { get; set; }

        /// <summary>
        /// Gets or sets the local port
        /// </summary>
        public int LocalPort { get; set; }

        /// <summary>
        /// Gets or sets the remote address
        /// </summary>
        public string RemoteAddress { get; set; }

        /// <summary>
        /// Gets or sets the remote port
        /// </summary>
        public int RemotePort { get; set; }

        /// <summary>
        /// Gets or sets the state
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets the service name
        /// </summary>
        public string ServiceName { get; set; }

        /// <summary>
        /// Gets or sets the timestamp
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the connection is suspicious
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
        /// Gets or sets the suspicious reason
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
        /// Gets the connection ID
        /// </summary>
        public string ConnectionId => $"{Protocol}_{LocalAddress}_{LocalPort}_{RemoteAddress}_{RemotePort}";

        /// <summary>
        /// Gets the local endpoint
        /// </summary>
        public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";

        /// <summary>
        /// Gets the remote endpoint
        /// </summary>
        public string RemoteEndpoint => $"{RemoteAddress}:{RemotePort}";

        /// <summary>
        /// Gets the status text
        /// </summary>
        public string StatusText => IsSuspicious ? "Suspicious" : "Normal";

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// Event arguments for network connection events
    /// </summary>
    public class NetworkConnectionEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the network connection
        /// </summary>
        public NetworkConnection Connection { get; }

        /// <summary>
        /// Initializes a new instance of the NetworkConnectionEventArgs class
        /// </summary>
        public NetworkConnectionEventArgs(NetworkConnection connection)
        {
            Connection = connection;
        }
    }
}