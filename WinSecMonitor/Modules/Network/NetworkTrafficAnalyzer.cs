using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Network
{
    /// <summary>
    /// Analyzes network traffic to detect unusual patterns such as data exfiltration
    /// </summary>
    public class NetworkTrafficAnalyzer
    {
        #region Private Fields

        private readonly Dictionary<string, ConnectionTrafficData> _connectionTrafficData;
        private readonly Dictionary<int, ProcessTrafficData> _processTrafficData;
        private readonly Dictionary<string, HostTrafficData> _hostTrafficData;
        private readonly object _lockObject = new object();

        // Thresholds for detecting unusual traffic
        private int _dataExfiltrationThresholdMB = 10; // MB per hour
        private int _connectionBurstThreshold = 20; // connections per minute
        private int _unusualPortThreshold = 5; // connections to unusual ports
        private int _unusualHostThreshold = 10; // connections to unusual hosts

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the NetworkTrafficAnalyzer class
        /// </summary>
        public NetworkTrafficAnalyzer()
        {
            _connectionTrafficData = new Dictionary<string, ConnectionTrafficData>();
            _processTrafficData = new Dictionary<int, ProcessTrafficData>();
            _hostTrafficData = new Dictionary<string, HostTrafficData>();

            LogInfo("NetworkTrafficAnalyzer initialized");
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the data exfiltration threshold in MB per hour
        /// </summary>
        public int DataExfiltrationThresholdMB
        {
            get { return _dataExfiltrationThresholdMB; }
            set { _dataExfiltrationThresholdMB = value; }
        }

        /// <summary>
        /// Gets or sets the connection burst threshold in connections per minute
        /// </summary>
        public int ConnectionBurstThreshold
        {
            get { return _connectionBurstThreshold; }
            set { _connectionBurstThreshold = value; }
        }

        /// <summary>
        /// Gets or sets the unusual port threshold
        /// </summary>
        public int UnusualPortThreshold
        {
            get { return _unusualPortThreshold; }
            set { _unusualPortThreshold = value; }
        }

        /// <summary>
        /// Gets or sets the unusual host threshold
        /// </summary>
        public int UnusualHostThreshold
        {
            get { return _unusualHostThreshold; }
            set { _unusualHostThreshold = value; }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Analyzes a network connection for unusual patterns
        /// </summary>
        public TrafficAnalysisResult AnalyzeConnection(NetworkConnection connection)
        {
            try
            {
                lock (_lockObject)
                {
                    // Create a result object
                    var result = new TrafficAnalysisResult
                    {
                        Connection = connection,
                        Timestamp = DateTime.Now
                    };

                    // Skip analysis for local connections
                    if (IsLocalConnection(connection))
                    {
                        result.IsUnusual = false;
                        result.Reason = "Local connection";
                        return result;
                    }

                    // Check for unusual ports
                    if (IsUnusualPort(connection.RemotePort))
                    {
                        result.IsUnusual = true;
                        result.Reason = $"Unusual port: {connection.RemotePort}";
                        LogWarning($"Unusual port detected: {connection.RemotePort} for process {connection.ProcessName} ({connection.ProcessId})");
                        return result;
                    }

                    // Update connection traffic data
                    UpdateConnectionTrafficData(connection);

                    // Update process traffic data
                    UpdateProcessTrafficData(connection);

                    // Update host traffic data
                    UpdateHostTrafficData(connection);

                    // Check for data exfiltration
                    if (IsDataExfiltration(connection))
                    {
                        result.IsUnusual = true;
                        result.Reason = "Possible data exfiltration";
                        LogWarning($"Possible data exfiltration detected for process {connection.ProcessName} ({connection.ProcessId})");
                        return result;
                    }

                    // Check for connection bursts
                    if (IsConnectionBurst(connection))
                    {
                        result.IsUnusual = true;
                        result.Reason = "Connection burst detected";
                        LogWarning($"Connection burst detected for process {connection.ProcessName} ({connection.ProcessId})");
                        return result;
                    }

                    // Check for unusual hosts
                    if (IsUnusualHost(connection))
                    {
                        result.IsUnusual = true;
                        result.Reason = $"Unusual host: {connection.RemoteAddress}";
                        LogWarning($"Unusual host detected: {connection.RemoteAddress} for process {connection.ProcessName} ({connection.ProcessId})");
                        return result;
                    }

                    // If we get here, the connection is not unusual
                    result.IsUnusual = false;
                    result.Reason = "Normal traffic pattern";
                    return result;
                }
            }
            catch (Exception ex)
            {
                LogError($"Error analyzing connection: {ex.Message}");
                return new TrafficAnalysisResult
                {
                    Connection = connection,
                    IsUnusual = false,
                    Reason = $"Error: {ex.Message}",
                    Timestamp = DateTime.Now
                };
            }
        }

        /// <summary>
        /// Records data transfer for a connection
        /// </summary>
        public void RecordDataTransfer(string connectionId, long bytesSent, long bytesReceived)
        {
            try
            {
                lock (_lockObject)
                {
                    if (_connectionTrafficData.TryGetValue(connectionId, out ConnectionTrafficData data))
                    {
                        data.BytesSent += bytesSent;
                        data.BytesReceived += bytesReceived;
                        data.LastActivity = DateTime.Now;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error recording data transfer: {ex.Message}");
            }
        }

        /// <summary>
        /// Clears all traffic data
        /// </summary>
        public void ClearTrafficData()
        {
            lock (_lockObject)
            {
                _connectionTrafficData.Clear();
                _processTrafficData.Clear();
                _hostTrafficData.Clear();
                LogInfo("Cleared all traffic data");
            }
        }

        /// <summary>
        /// Gets traffic data for a process
        /// </summary>
        public ProcessTrafficData GetProcessTrafficData(int processId)
        {
            lock (_lockObject)
            {
                if (_processTrafficData.TryGetValue(processId, out ProcessTrafficData data))
                {
                    return data;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets traffic data for a host
        /// </summary>
        public HostTrafficData GetHostTrafficData(string host)
        {
            lock (_lockObject)
            {
                if (_hostTrafficData.TryGetValue(host, out HostTrafficData data))
                {
                    return data;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets all process traffic data
        /// </summary>
        public List<ProcessTrafficData> GetAllProcessTrafficData()
        {
            lock (_lockObject)
            {
                return _processTrafficData.Values.ToList();
            }
        }

        /// <summary>
        /// Gets all host traffic data
        /// </summary>
        public List<HostTrafficData> GetAllHostTrafficData()
        {
            lock (_lockObject)
            {
                return _hostTrafficData.Values.ToList();
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Updates the connection traffic data
        /// </summary>
        private void UpdateConnectionTrafficData(NetworkConnection connection)
        {
            if (!_connectionTrafficData.TryGetValue(connection.ConnectionId, out ConnectionTrafficData data))
            {
                data = new ConnectionTrafficData
                {
                    ConnectionId = connection.ConnectionId,
                    ProcessId = connection.ProcessId,
                    ProcessName = connection.ProcessName,
                    LocalEndpoint = connection.LocalEndpoint,
                    RemoteEndpoint = connection.RemoteEndpoint,
                    Protocol = connection.Protocol,
                    FirstSeen = DateTime.Now,
                    LastActivity = DateTime.Now,
                    BytesSent = 0,
                    BytesReceived = 0
                };

                _connectionTrafficData[connection.ConnectionId] = data;
            }
            else
            {
                data.LastActivity = DateTime.Now;
            }
        }

        /// <summary>
        /// Updates the process traffic data
        /// </summary>
        private void UpdateProcessTrafficData(NetworkConnection connection)
        {
            if (!_processTrafficData.TryGetValue(connection.ProcessId, out ProcessTrafficData data))
            {
                data = new ProcessTrafficData
                {
                    ProcessId = connection.ProcessId,
                    ProcessName = connection.ProcessName,
                    FirstSeen = DateTime.Now,
                    LastActivity = DateTime.Now,
                    TotalConnections = 1,
                    ActiveConnections = 1,
                    UniqueRemoteHosts = new HashSet<string> { connection.RemoteAddress },
                    UniqueRemotePorts = new HashSet<int> { connection.RemotePort },
                    ConnectionTimes = new List<DateTime> { DateTime.Now }
                };

                _processTrafficData[connection.ProcessId] = data;
            }
            else
            {
                data.LastActivity = DateTime.Now;
                data.TotalConnections++;
                data.ActiveConnections++;
                data.UniqueRemoteHosts.Add(connection.RemoteAddress);
                data.UniqueRemotePorts.Add(connection.RemotePort);
                data.ConnectionTimes.Add(DateTime.Now);

                // Keep only the last 100 connection times to avoid memory issues
                if (data.ConnectionTimes.Count > 100)
                {
                    data.ConnectionTimes.RemoveAt(0);
                }
            }
        }

        /// <summary>
        /// Updates the host traffic data
        /// </summary>
        private void UpdateHostTrafficData(NetworkConnection connection)
        {
            if (!_hostTrafficData.TryGetValue(connection.RemoteAddress, out HostTrafficData data))
            {
                data = new HostTrafficData
                {
                    Host = connection.RemoteAddress,
                    FirstSeen = DateTime.Now,
                    LastActivity = DateTime.Now,
                    TotalConnections = 1,
                    ActiveConnections = 1,
                    UniqueProcesses = new HashSet<int> { connection.ProcessId },
                    UniqueLocalPorts = new HashSet<int> { connection.LocalPort },
                    ConnectionTimes = new List<DateTime> { DateTime.Now }
                };

                _hostTrafficData[connection.RemoteAddress] = data;
            }
            else
            {
                data.LastActivity = DateTime.Now;
                data.TotalConnections++;
                data.ActiveConnections++;
                data.UniqueProcesses.Add(connection.ProcessId);
                data.UniqueLocalPorts.Add(connection.LocalPort);
                data.ConnectionTimes.Add(DateTime.Now);

                // Keep only the last 100 connection times to avoid memory issues
                if (data.ConnectionTimes.Count > 100)
                {
                    data.ConnectionTimes.RemoveAt(0);
                }
            }
        }

        /// <summary>
        /// Checks if a connection is a local connection
        /// </summary>
        private bool IsLocalConnection(NetworkConnection connection)
        {
            // Check if the remote address is a local address
            return connection.RemoteAddress == "127.0.0.1" ||
                   connection.RemoteAddress == "::1" ||
                   connection.RemoteAddress.StartsWith("192.168.") ||
                   connection.RemoteAddress.StartsWith("10.") ||
                   (connection.RemoteAddress.StartsWith("172.") && IsPrivateSubnet172(connection.RemoteAddress)) ||
                   connection.RemoteAddress.StartsWith("169.254.") ||
                   connection.RemoteAddress == "*";
        }

        /// <summary>
        /// Checks if an IP address is in the 172.16.0.0/12 private subnet
        /// </summary>
        private bool IsPrivateSubnet172(string ipAddress)
        {
            try
            {
                string[] octets = ipAddress.Split('.');
                if (octets.Length == 4 && int.TryParse(octets[1], out int secondOctet))
                {
                    return secondOctet >= 16 && secondOctet <= 31;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a port is unusual
        /// </summary>
        private bool IsUnusualPort(int port)
        {
            // Common ports that are not unusual
            int[] commonPorts = new int[]
            {
                20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                1433, 3306, 3389, 5432, 8080, 8443
            };

            // Check if the port is in the common ports list
            return !commonPorts.Contains(port) && port > 1024 && port != 0;
        }

        /// <summary>
        /// Checks if a connection is part of a data exfiltration attempt
        /// </summary>
        private bool IsDataExfiltration(NetworkConnection connection)
        {
            // Check if the process has sent a large amount of data in a short period of time
            if (_processTrafficData.TryGetValue(connection.ProcessId, out ProcessTrafficData data))
            {
                // Calculate the total bytes sent in the last hour
                long totalBytesSent = 0;
                foreach (var connData in _connectionTrafficData.Values)
                {
                    if (connData.ProcessId == connection.ProcessId &&
                        (DateTime.Now - connData.LastActivity).TotalHours < 1)
                    {
                        totalBytesSent += connData.BytesSent;
                    }
                }

                // Convert bytes to MB
                double totalMBSent = totalBytesSent / (1024.0 * 1024.0);

                // Check if the total MB sent exceeds the threshold
                return totalMBSent > _dataExfiltrationThresholdMB;
            }

            return false;
        }

        /// <summary>
        /// Checks if a connection is part of a connection burst
        /// </summary>
        private bool IsConnectionBurst(NetworkConnection connection)
        {
            // Check if the process has made a large number of connections in a short period of time
            if (_processTrafficData.TryGetValue(connection.ProcessId, out ProcessTrafficData data))
            {
                // Count the number of connections in the last minute
                int connectionsInLastMinute = data.ConnectionTimes.Count(t => (DateTime.Now - t).TotalMinutes < 1);

                // Check if the number of connections exceeds the threshold
                return connectionsInLastMinute > _connectionBurstThreshold;
            }

            return false;
        }

        /// <summary>
        /// Checks if a host is unusual
        /// </summary>
        private bool IsUnusualHost(NetworkConnection connection)
        {
            // Check if the process has connected to a large number of unique hosts
            if (_processTrafficData.TryGetValue(connection.ProcessId, out ProcessTrafficData data))
            {
                // Check if the number of unique hosts exceeds the threshold
                return data.UniqueRemoteHosts.Count > _unusualHostThreshold;
            }

            return false;
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [NetworkTrafficAnalyzer] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private static void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [NetworkTrafficAnalyzer] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [NetworkTrafficAnalyzer] {message}");
        }

        #endregion
    }

    /// <summary>
    /// Represents traffic data for a connection
    /// </summary>
    public class ConnectionTrafficData
    {
        /// <summary>
        /// Gets or sets the connection ID
        /// </summary>
        public string ConnectionId { get; set; }

        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets the local endpoint
        /// </summary>
        public string LocalEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the remote endpoint
        /// </summary>
        public string RemoteEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the protocol
        /// </summary>
        public ProtocolType Protocol { get; set; }

        /// <summary>
        /// Gets or sets the first seen timestamp
        /// </summary>
        public DateTime FirstSeen { get; set; }

        /// <summary>
        /// Gets or sets the last activity timestamp
        /// </summary>
        public DateTime LastActivity { get; set; }

        /// <summary>
        /// Gets or sets the bytes sent
        /// </summary>
        public long BytesSent { get; set; }

        /// <summary>
        /// Gets or sets the bytes received
        /// </summary>
        public long BytesReceived { get; set; }
    }

    /// <summary>
    /// Represents traffic data for a process
    /// </summary>
    public class ProcessTrafficData
    {
        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets the first seen timestamp
        /// </summary>
        public DateTime FirstSeen { get; set; }

        /// <summary>
        /// Gets or sets the last activity timestamp
        /// </summary>
        public DateTime LastActivity { get; set; }

        /// <summary>
        /// Gets or sets the total number of connections
        /// </summary>
        public int TotalConnections { get; set; }

        /// <summary>
        /// Gets or sets the number of active connections
        /// </summary>
        public int ActiveConnections { get; set; }

        /// <summary>
        /// Gets or sets the unique remote hosts
        /// </summary>
        public HashSet<string> UniqueRemoteHosts { get; set; }

        /// <summary>
        /// Gets or sets the unique remote ports
        /// </summary>
        public HashSet<int> UniqueRemotePorts { get; set; }

        /// <summary>
        /// Gets or sets the connection times
        /// </summary>
        public List<DateTime> ConnectionTimes { get; set; }
    }

    /// <summary>
    /// Represents traffic data for a host
    /// </summary>
    public class HostTrafficData
    {
        /// <summary>
        /// Gets or sets the host
        /// </summary>
        public string Host { get; set; }

        /// <summary>
        /// Gets or sets the first seen timestamp
        /// </summary>
        public DateTime FirstSeen { get; set; }

        /// <summary>
        /// Gets or sets the last activity timestamp
        /// </summary>
        public DateTime LastActivity { get; set; }

        /// <summary>
        /// Gets or sets the total number of connections
        /// </summary>
        public int TotalConnections { get; set; }

        /// <summary>
        /// Gets or sets the number of active connections
        /// </summary>
        public int ActiveConnections { get; set; }

        /// <summary>
        /// Gets or sets the unique processes
        /// </summary>
        public HashSet<int> UniqueProcesses { get; set; }

        /// <summary>
        /// Gets or sets the unique local ports
        /// </summary>
        public HashSet<int> UniqueLocalPorts { get; set; }

        /// <summary>
        /// Gets or sets the connection times
        /// </summary>
        public List<DateTime> ConnectionTimes { get; set; }
    }

    /// <summary>
    /// Represents the result of a traffic analysis
    /// </summary>
    public class TrafficAnalysisResult
    {
        /// <summary>
        /// Gets or sets the connection
        /// </summary>
        public NetworkConnection Connection { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the traffic is unusual
        /// </summary>
        public bool IsUnusual { get; set; }

        /// <summary>
        /// Gets or sets the reason for the analysis result
        /// </summary>
        public string Reason { get; set; }

        /// <summary>
        /// Gets or sets the timestamp
        /// </summary>
        public DateTime Timestamp { get; set; }
    }
}