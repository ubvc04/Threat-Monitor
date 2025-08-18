using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.User
{
    public class RDPSession
    {
        public string Username { get; set; }
        public string ClientName { get; set; }
        public string ClientAddress { get; set; }
        public string SessionState { get; set; }
        public DateTime ConnectTime { get; set; }
        public DateTime? DisconnectTime { get; set; }
        public TimeSpan? Duration => DisconnectTime.HasValue ? DisconnectTime.Value - ConnectTime : (TimeSpan?)null;
        public bool IsActive => SessionState == "Active";
        public bool IsSuspicious { get; set; }
        public string SuspiciousReason { get; set; }

        public string FormattedConnectTime => ConnectTime.ToString("yyyy-MM-dd HH:mm:ss");
        public string FormattedDisconnectTime => DisconnectTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Still connected";
        public string FormattedDuration => Duration.HasValue ? 
            $"{Duration.Value.Hours:D2}:{Duration.Value.Minutes:D2}:{Duration.Value.Seconds:D2}" : 
            "Active";
    }

    public class RDPSessionMonitor
    {
        private readonly Logger _logger;
        private readonly Timer _refreshTimer;
        private readonly Dispatcher _dispatcher;
        private readonly List<string> _knownSafeIPs;

        public ObservableCollection<RDPSession> ActiveSessions { get; private set; }
        public ObservableCollection<RDPSession> SessionHistory { get; private set; }
        public ObservableCollection<RDPSession> SuspiciousSessions { get; private set; }

        public event EventHandler RDPSessionsUpdated;
        public event EventHandler SuspiciousRDPActivityDetected;

        public RDPSessionMonitor(Dispatcher dispatcher = null)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;
            
            ActiveSessions = new ObservableCollection<RDPSession>();
            SessionHistory = new ObservableCollection<RDPSession>();
            SuspiciousSessions = new ObservableCollection<RDPSession>();

            // Initialize list of known safe IPs (could be loaded from config)
            _knownSafeIPs = new List<string> { "127.0.0.1", "192.168.1." };

            // Set up timer for periodic refresh (every 60 seconds)
            _refreshTimer = new Timer(60000);
            _refreshTimer.Elapsed += async (s, e) => await RefreshSessionsAsync();
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogDebug("Initializing RDPSessionMonitor");
                await RefreshSessionsAsync();
                _logger.LogInformation("RDPSessionMonitor initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing RDPSessionMonitor");
            }
        }

        public void StartMonitoring()
        {
            try
            {
                _logger.LogDebug("Starting RDP session monitoring");
                _refreshTimer.Start();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error starting RDP session monitoring");
            }
        }

        public void StopMonitoring()
        {
            try
            {
                _logger.LogDebug("Stopping RDP session monitoring");
                _refreshTimer.Stop();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error stopping RDP session monitoring");
            }
        }

        public async Task RefreshSessionsAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing RDP sessions");

                var currentSessions = await Task.Run(() => GetCurrentRDPSessions());
                var historicalSessions = await Task.Run(() => GetRDPSessionHistory());
                var suspiciousSessions = DetectSuspiciousRDPActivity(currentSessions, historicalSessions);

                // Update collections on the UI thread if dispatcher is available
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        UpdateSessionCollection(ActiveSessions, currentSessions);
                        UpdateSessionCollection(SessionHistory, historicalSessions);
                        
                        if (suspiciousSessions.Any())
                        {
                            foreach (var suspiciousSession in suspiciousSessions)
                            {
                                if (!SuspiciousSessions.Any(s => s.Username == suspiciousSession.Username && 
                                                              s.ClientAddress == suspiciousSession.ClientAddress &&
                                                              s.ConnectTime == suspiciousSession.ConnectTime))
                                {
                                    SuspiciousSessions.Insert(0, suspiciousSession);
                                }
                            }
                            
                            // Limit the number of suspicious sessions to keep
                            while (SuspiciousSessions.Count > 100)
                            {
                                SuspiciousSessions.RemoveAt(SuspiciousSessions.Count - 1);
                            }
                            
                            SuspiciousRDPActivityDetected?.Invoke(this, EventArgs.Empty);
                        }
                        
                        RDPSessionsUpdated?.Invoke(this, EventArgs.Empty);
                    });
                }
                else
                {
                    UpdateSessionCollection(ActiveSessions, currentSessions);
                    UpdateSessionCollection(SessionHistory, historicalSessions);
                    
                    if (suspiciousSessions.Any())
                    {
                        foreach (var suspiciousSession in suspiciousSessions)
                        {
                            if (!SuspiciousSessions.Any(s => s.Username == suspiciousSession.Username && 
                                                          s.ClientAddress == suspiciousSession.ClientAddress &&
                                                          s.ConnectTime == suspiciousSession.ConnectTime))
                            {
                                SuspiciousSessions.Insert(0, suspiciousSession);
                            }
                        }
                        
                        // Limit the number of suspicious sessions to keep
                        while (SuspiciousSessions.Count > 100)
                        {
                            SuspiciousSessions.RemoveAt(SuspiciousSessions.Count - 1);
                        }
                        
                        SuspiciousRDPActivityDetected?.Invoke(this, EventArgs.Empty);
                    }
                    
                    RDPSessionsUpdated?.Invoke(this, EventArgs.Empty);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing RDP sessions");
            }
        }

        private List<RDPSession> GetCurrentRDPSessions()
        {
            var sessions = new List<RDPSession>();

            try
            {
                // Method 1: Using WMI to query Terminal Services sessions
                using (var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2", 
                    "SELECT * FROM Win32_TerminalSession WHERE ClientName IS NOT NULL"))
                {
                    foreach (var queryObj in searcher.Get())
                    {
                        try
                        {
                            var session = new RDPSession
                            {
                                ClientName = queryObj["ClientName"]?.ToString(),
                                ClientAddress = queryObj["ClientIPAddress"]?.ToString(),
                                SessionState = "Active",
                                ConnectTime = DateTime.Now, // WMI doesn't provide connect time directly
                                IsActive = true
                            };

                            // Try to get the username from associated processes
                            session.Username = GetUsernameForSession(Convert.ToInt32(queryObj["SessionId"]));

                            sessions.Add(session);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogException(ex, "Error processing terminal session WMI object");
                        }
                    }
                }

                // Method 2: Using qwinsta command as fallback
                if (!sessions.Any())
                {
                    sessions.AddRange(GetSessionsFromQwinsta());
                }
            }
            catch (ManagementException ex)
            {
                _logger.LogException(ex, "WMI error when querying terminal sessions");
                // Fallback to qwinsta command
                sessions.AddRange(GetSessionsFromQwinsta());
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting current RDP sessions");
            }

            return sessions;
        }

        private List<RDPSession> GetSessionsFromQwinsta()
        {
            var sessions = new List<RDPSession>();

            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "qwinsta",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse qwinsta output
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 1; i < lines.Length; i++) // Skip header line
                {
                    string line = lines[i].Trim();
                    string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    if (parts.Length >= 3)
                    {
                        string username = parts[0];
                        string sessionId = parts[1];
                        string state = parts[2];

                        // Only include active or disconnected sessions with usernames
                        if ((state == "Active" || state == "Disc") && !string.IsNullOrEmpty(username) && username != "services" && username != "console")
                        {
                            var session = new RDPSession
                            {
                                Username = username,
                                SessionState = state == "Active" ? "Active" : "Disconnected",
                                ConnectTime = DateTime.Now, // qwinsta doesn't provide connect time
                                IsActive = state == "Active"
                            };

                            sessions.Add(session);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting sessions from qwinsta command");
            }

            return sessions;
        }

        private string GetUsernameForSession(int sessionId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2", 
                    $"SELECT * FROM Win32_Process WHERE SessionId = {sessionId}"))
                {
                    foreach (var process in searcher.Get())
                    {
                        try
                        {
                            string[] owner = new string[2];
                            process.InvokeMethod("GetOwner", (object[])owner);
                            if (!string.IsNullOrEmpty(owner[0]))
                            {
                                return owner[0]; // Return username
                            }
                        }
                        catch
                        {
                            // Ignore errors for individual processes
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error getting username for session ID {sessionId}");
            }

            return "Unknown";
        }

        private List<RDPSession> GetRDPSessionHistory()
        {
            var sessions = new List<RDPSession>();

            try
            {
                // Use the Windows Event Log to get historical RDP sessions
                // Event ID 4624 (Logon) with Logon Type 10 (RemoteInteractive)
                // Event ID 4634 (Logoff)

                // This is a simplified implementation
                // In a real application, you would parse the Windows Event Log for RDP events
                // and build a comprehensive session history

                // For demonstration purposes, we'll just add some sample historical sessions
                // In a real implementation, this would be replaced with actual event log parsing
                if (SessionHistory.Count == 0)
                {
                    // Only add sample data if we don't have any history yet
                    var random = new Random();
                    var users = new[] { "Administrator", "JohnDoe", "JaneSmith", "ITAdmin" };
                    var ips = new[] { "192.168.1.100", "192.168.1.101", "10.0.0.15", "172.16.0.25" };

                    for (int i = 0; i < 10; i++)
                    {
                        var connectTime = DateTime.Now.AddDays(-random.Next(1, 30)).AddHours(-random.Next(1, 24));
                        var disconnectTime = connectTime.AddMinutes(random.Next(5, 180));

                        sessions.Add(new RDPSession
                        {
                            Username = users[random.Next(users.Length)],
                            ClientName = $"DESKTOP-{random.Next(1000, 9999)}",
                            ClientAddress = ips[random.Next(ips.Length)],
                            SessionState = "Disconnected",
                            ConnectTime = connectTime,
                            DisconnectTime = disconnectTime,
                            IsActive = false
                        });
                    }
                }
                else
                {
                    // If we already have history, just return it
                    sessions.AddRange(SessionHistory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting RDP session history");
            }

            return sessions;
        }

        private List<RDPSession> DetectSuspiciousRDPActivity(List<RDPSession> currentSessions, List<RDPSession> historicalSessions)
        {
            var suspiciousSessions = new List<RDPSession>();

            try
            {
                // Check for connections from unknown IP addresses
                foreach (var session in currentSessions.Concat(historicalSessions))
                {
                    if (!string.IsNullOrEmpty(session.ClientAddress) && 
                        !_knownSafeIPs.Any(ip => session.ClientAddress.StartsWith(ip)))
                    {
                        session.IsSuspicious = true;
                        session.SuspiciousReason = $"Connection from unknown IP address: {session.ClientAddress}";
                        suspiciousSessions.Add(session);
                    }
                }

                // Check for connections outside business hours (8 AM - 6 PM)
                foreach (var session in currentSessions.Concat(historicalSessions))
                {
                    if (session.ConnectTime.Hour < 8 || session.ConnectTime.Hour >= 18)
                    {
                        session.IsSuspicious = true;
                        session.SuspiciousReason = $"Connection outside business hours: {session.FormattedConnectTime}";
                        suspiciousSessions.Add(session);
                    }
                }

                // Check for unusually long sessions (more than 8 hours)
                foreach (var session in historicalSessions.Where(s => s.Duration.HasValue))
                {
                    if (session.Duration.Value.TotalHours > 8)
                    {
                        session.IsSuspicious = true;
                        session.SuspiciousReason = $"Unusually long session: {session.FormattedDuration}";
                        suspiciousSessions.Add(session);
                    }
                }

                // Check for multiple concurrent sessions for the same user
                var userGroups = currentSessions.GroupBy(s => s.Username).Where(g => g.Count() > 1);
                foreach (var group in userGroups)
                {
                    foreach (var session in group)
                    {
                        session.IsSuspicious = true;
                        session.SuspiciousReason = $"Multiple concurrent sessions for user: {session.Username}";
                        suspiciousSessions.Add(session);
                    }
                }

                // Check for connections from foreign countries (would require IP geolocation)
                // This is a placeholder for a real implementation that would use IP geolocation
                // For demonstration, we'll just flag any non-private IP as potentially foreign
                foreach (var session in currentSessions.Concat(historicalSessions))
                {
                    if (!string.IsNullOrEmpty(session.ClientAddress) && 
                        !IsPrivateIPAddress(session.ClientAddress) && 
                        session.ClientAddress != "127.0.0.1")
                    {
                        session.IsSuspicious = true;
                        session.SuspiciousReason = $"Potential connection from outside the local network: {session.ClientAddress}";
                        suspiciousSessions.Add(session);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error detecting suspicious RDP activity");
            }

            return suspiciousSessions;
        }

        private bool IsPrivateIPAddress(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress address))
                {
                    byte[] bytes = address.GetAddressBytes();
                    
                    // Check for private IP ranges
                    return (bytes[0] == 10) || // 10.0.0.0/8
                           (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || // 172.16.0.0/12
                           (bytes[0] == 192 && bytes[1] == 168); // 192.168.0.0/16
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error checking if IP address is private: {ipAddress}");
            }
            
            return false;
        }

        private void UpdateSessionCollection(ObservableCollection<RDPSession> collection, List<RDPSession> newSessions)
        {
            // For active sessions, replace the entire collection
            if (collection == ActiveSessions)
            {
                collection.Clear();
                foreach (var session in newSessions.OrderByDescending(s => s.ConnectTime))
                {
                    collection.Add(session);
                }
            }
            // For historical sessions, add new ones and maintain order
            else
            {
                // Add new sessions that don't already exist in the collection
                foreach (var newSession in newSessions)
                {
                    if (!collection.Any(s => s.Username == newSession.Username && 
                                           s.ClientAddress == newSession.ClientAddress &&
                                           s.ConnectTime == newSession.ConnectTime))
                    {
                        collection.Add(newSession);
                    }
                }

                // Sort the collection by connect time (descending)
                var sortedSessions = collection.OrderByDescending(s => s.ConnectTime).ToList();
                collection.Clear();
                foreach (var session in sortedSessions)
                {
                    collection.Add(session);
                }

                // Limit the collection size
                while (collection.Count > 100)
                {
                    collection.RemoveAt(collection.Count - 1);
                }
            }
        }
    }
}