using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.User
{
    public class LogonEvent
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }  // Logon, Logoff, Failed Logon
        public string Username { get; set; }
        public string Domain { get; set; }
        public string WorkstationName { get; set; }
        public string IpAddress { get; set; }
        public string LogonType { get; set; }  // Interactive, Network, Service, etc.
        public int EventId { get; set; }
        public string Status { get; set; }     // Success, Failure
        public string FailureReason { get; set; } // For failed logons
        public string ProcessName { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspiciousReason { get; set; }

        public string FormattedTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
        public string FormattedEventType => $"{EventType} ({EventId})";
    }

    public class AuthenticationMonitor
    {
        private readonly Logger _logger;
        private readonly Timer _refreshTimer;
        private readonly Dispatcher _dispatcher;
        private DateTime _lastEventTime;
        private const string SecurityLogName = "Security";
        private const int MaxEventsToRetrieve = 100;

        // Event IDs for authentication events
        private static readonly int[] LogonEventIds = { 4624 };           // Successful logon
        private static readonly int[] LogoffEventIds = { 4634, 4647 };    // Logoff
        private static readonly int[] FailedLogonEventIds = { 4625 };     // Failed logon
        private static readonly int[] AccountLockoutEventIds = { 4740 };  // Account lockout

        // Dictionary to map logon types to readable descriptions
        private static readonly Dictionary<string, string> LogonTypeMap = new Dictionary<string, string>
        {
            { "2", "Interactive" },
            { "3", "Network" },
            { "4", "Batch" },
            { "5", "Service" },
            { "7", "Unlock" },
            { "8", "NetworkCleartext" },
            { "9", "NewCredentials" },
            { "10", "RemoteInteractive (RDP)" },
            { "11", "CachedInteractive" }
        };

        // Dictionary to map failure status/substatus codes to readable descriptions
        private static readonly Dictionary<string, string> FailureReasonMap = new Dictionary<string, string>
        {
            { "0xC0000064", "User does not exist" },
            { "0xC000006A", "Incorrect password" },
            { "0xC0000234", "Account locked out" },
            { "0xC0000072", "Account disabled" },
            { "0xC000006F", "Outside permitted hours" },
            { "0xC0000070", "Workstation restriction" },
            { "0xC0000193", "Account expired" },
            { "0xC0000071", "Password expired" },
            { "0xC0000133", "Clocks out of sync" },
            { "0xC0000224", "Password change required" },
            { "0xC0000225", "Windows bug - evidently not a real authentication failure" },
            { "0xC000015B", "Logon type not granted" }
        };

        public ObservableCollection<LogonEvent> RecentLogonEvents { get; private set; }
        public ObservableCollection<LogonEvent> RecentFailedLogonEvents { get; private set; }
        public ObservableCollection<LogonEvent> SuspiciousEvents { get; private set; }

        public event EventHandler LogonEventsUpdated;
        public event EventHandler SuspiciousActivityDetected;

        public AuthenticationMonitor(Dispatcher dispatcher = null)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;
            _lastEventTime = DateTime.Now.AddHours(-1); // Start by getting events from the last hour

            RecentLogonEvents = new ObservableCollection<LogonEvent>();
            RecentFailedLogonEvents = new ObservableCollection<LogonEvent>();
            SuspiciousEvents = new ObservableCollection<LogonEvent>();

            // Set up timer for periodic refresh (every 30 seconds)
            _refreshTimer = new Timer(30000);
            _refreshTimer.Elapsed += async (s, e) => await RefreshEventsAsync();
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogDebug("Initializing AuthenticationMonitor");
                await RefreshEventsAsync();
                _logger.LogInformation("AuthenticationMonitor initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing AuthenticationMonitor");
                throw;
            }
        }

        public void StartMonitoring()
        {
            try
            {
                _logger.LogDebug("Starting authentication monitoring");
                _refreshTimer.Start();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error starting authentication monitoring");
                throw;
            }
        }

        public void StopMonitoring()
        {
            try
            {
                _logger.LogDebug("Stopping authentication monitoring");
                _refreshTimer.Stop();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error stopping authentication monitoring");
            }
        }

        public async Task RefreshEventsAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing authentication events");

                // Check if Security log is accessible
                if (!EventLogExists(SecurityLogName))
                {
                    _logger.LogWarning($"Security event log is not accessible. This may be due to insufficient permissions.");
                    return;
                }

                var newLogonEvents = await Task.Run(() => GetLogonEvents());
                var newFailedLogonEvents = await Task.Run(() => GetFailedLogonEvents());

                // Update the last event time to the most recent event
                if (newLogonEvents.Any() || newFailedLogonEvents.Any())
                {
                    var allEvents = newLogonEvents.Concat(newFailedLogonEvents);
                    if (allEvents.Any())
                    {
                        _lastEventTime = allEvents.Max(e => e.Timestamp);
                    }
                }

                // Check for suspicious activity
                var suspiciousEvents = DetectSuspiciousActivity(newLogonEvents, newFailedLogonEvents);

                // Update collections on the UI thread if dispatcher is available
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        UpdateEventCollection(RecentLogonEvents, newLogonEvents);
                        UpdateEventCollection(RecentFailedLogonEvents, newFailedLogonEvents);
                        
                        if (suspiciousEvents.Any())
                        {
                            foreach (var suspiciousEvent in suspiciousEvents)
                            {
                                SuspiciousEvents.Insert(0, suspiciousEvent);
                            }
                            
                            // Limit the number of suspicious events to keep
                            while (SuspiciousEvents.Count > MaxEventsToRetrieve)
                            {
                                SuspiciousEvents.RemoveAt(SuspiciousEvents.Count - 1);
                            }
                            
                            SuspiciousActivityDetected?.Invoke(this, EventArgs.Empty);
                        }
                        
                        LogonEventsUpdated?.Invoke(this, EventArgs.Empty);
                    });
                }
                else
                {
                    UpdateEventCollection(RecentLogonEvents, newLogonEvents);
                    UpdateEventCollection(RecentFailedLogonEvents, newFailedLogonEvents);
                    
                    if (suspiciousEvents.Any())
                    {
                        foreach (var suspiciousEvent in suspiciousEvents)
                        {
                            SuspiciousEvents.Insert(0, suspiciousEvent);
                        }
                        
                        // Limit the number of suspicious events to keep
                        while (SuspiciousEvents.Count > MaxEventsToRetrieve)
                        {
                            SuspiciousEvents.RemoveAt(SuspiciousEvents.Count - 1);
                        }
                        
                        SuspiciousActivityDetected?.Invoke(this, EventArgs.Empty);
                    }
                    
                    LogonEventsUpdated?.Invoke(this, EventArgs.Empty);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogException(ex, "Access denied to Security event log. Run the application as Administrator.");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing authentication events");
            }
        }

        private List<LogonEvent> GetLogonEvents()
        {
            var events = new List<LogonEvent>();

            try
            {
                // Query for successful logon events
                string logonQuery = CreateEventQuery(LogonEventIds);
                events.AddRange(QueryEvents(logonQuery, "Logon", "Success"));

                // Query for logoff events
                string logoffQuery = CreateEventQuery(LogoffEventIds);
                events.AddRange(QueryEvents(logoffQuery, "Logoff", "Success"));
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error retrieving logon events");
            }

            return events;
        }

        private List<LogonEvent> GetFailedLogonEvents()
        {
            var events = new List<LogonEvent>();

            try
            {
                // Query for failed logon events
                string failedLogonQuery = CreateEventQuery(FailedLogonEventIds);
                events.AddRange(QueryEvents(failedLogonQuery, "Failed Logon", "Failure"));

                // Query for account lockout events
                string lockoutQuery = CreateEventQuery(AccountLockoutEventIds);
                events.AddRange(QueryEvents(lockoutQuery, "Account Lockout", "Failure"));
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error retrieving failed logon events");
            }

            return events;
        }

        private string CreateEventQuery(int[] eventIds)
        {
            string eventIdFilter = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
            return $"<QueryList>" +
                   $"<Query Id=\"0\" Path=\"Security\">" +
                   $"<Select Path=\"Security\">*[System[({eventIdFilter}) and TimeCreated[@SystemTime&gt;='{_lastEventTime.ToUniversalTime():o}']]]</Select>" +
                   $"</Query>" +
                   $"</QueryList>";
        }

        private List<LogonEvent> QueryEvents(string query, string eventType, string status)
        {
            var events = new List<LogonEvent>();

            try
            {
                using (var eventLogReader = new EventLogReader(new EventLogQuery(SecurityLogName, PathType.LogName, query)))
                {
                    EventRecord eventRecord;
                    int count = 0;

                    while ((eventRecord = eventLogReader.ReadEvent()) != null && count < MaxEventsToRetrieve)
                    {
                        try
                        {
                            var logonEvent = ParseEventRecord(eventRecord, eventType, status);
                            if (logonEvent != null)
                            {
                                events.Add(logonEvent);
                                count++;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogException(ex, $"Error parsing event record ID {eventRecord.Id}");
                        }
                        finally
                        {
                            eventRecord.Dispose();
                        }
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                _logger.LogWarning("Security event log not found");
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning("Access denied to Security event log. Run the application as Administrator.");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error querying {eventType} events");
            }

            return events;
        }

        private LogonEvent ParseEventRecord(EventRecord eventRecord, string eventType, string status)
        {
            try
            {
                var logonEvent = new LogonEvent
                {
                    Timestamp = eventRecord.TimeCreated ?? DateTime.Now,
                    EventType = eventType,
                    EventId = eventRecord.Id,
                    Status = status
                };

                // Extract event-specific properties based on event ID
                switch (eventRecord.Id)
                {
                    case 4624: // Successful logon
                        ExtractLogonProperties(eventRecord, logonEvent);
                        break;
                    case 4625: // Failed logon
                        ExtractFailedLogonProperties(eventRecord, logonEvent);
                        break;
                    case 4634: // Logoff
                    case 4647: // User initiated logoff
                        ExtractLogoffProperties(eventRecord, logonEvent);
                        break;
                    case 4740: // Account lockout
                        ExtractAccountLockoutProperties(eventRecord, logonEvent);
                        break;
                }

                return logonEvent;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error parsing event record ID {eventRecord.Id}");
                return null;
            }
        }

        private void ExtractLogonProperties(EventRecord eventRecord, LogonEvent logonEvent)
        {
            if (eventRecord.Properties.Count >= 16)
            {
                logonEvent.Username = eventRecord.Properties[5].Value?.ToString();
                logonEvent.Domain = eventRecord.Properties[6].Value?.ToString();
                logonEvent.LogonType = GetLogonTypeDescription(eventRecord.Properties[8].Value?.ToString());
                logonEvent.WorkstationName = eventRecord.Properties[11].Value?.ToString();
                logonEvent.IpAddress = eventRecord.Properties[18].Value?.ToString();
                logonEvent.ProcessName = eventRecord.Properties[17].Value?.ToString();
            }
        }

        private void ExtractFailedLogonProperties(EventRecord eventRecord, LogonEvent logonEvent)
        {
            if (eventRecord.Properties.Count >= 16)
            {
                logonEvent.Username = eventRecord.Properties[5].Value?.ToString();
                logonEvent.Domain = eventRecord.Properties[6].Value?.ToString();
                logonEvent.LogonType = GetLogonTypeDescription(eventRecord.Properties[10].Value?.ToString());
                logonEvent.WorkstationName = eventRecord.Properties[13].Value?.ToString();
                logonEvent.IpAddress = eventRecord.Properties[19].Value?.ToString();

                // Extract failure reason
                string statusCode = eventRecord.Properties[7].Value?.ToString();
                string subStatusCode = eventRecord.Properties[9].Value?.ToString();
                logonEvent.FailureReason = GetFailureReason(statusCode, subStatusCode);
            }
        }

        private void ExtractLogoffProperties(EventRecord eventRecord, LogonEvent logonEvent)
        {
            if (eventRecord.Properties.Count >= 3)
            {
                logonEvent.Username = eventRecord.Properties[1].Value?.ToString();
                logonEvent.Domain = eventRecord.Properties[2].Value?.ToString();
            }
        }

        private void ExtractAccountLockoutProperties(EventRecord eventRecord, LogonEvent logonEvent)
        {
            if (eventRecord.Properties.Count >= 2)
            {
                logonEvent.Username = eventRecord.Properties[0].Value?.ToString();
                logonEvent.Domain = eventRecord.Properties[1].Value?.ToString();
                logonEvent.FailureReason = "Account locked out";
            }
        }

        private string GetLogonTypeDescription(string logonTypeId)
        {
            if (string.IsNullOrEmpty(logonTypeId))
                return "Unknown";

            return LogonTypeMap.TryGetValue(logonTypeId, out string description) ? description : $"Type {logonTypeId}";
        }

        private string GetFailureReason(string statusCode, string subStatusCode)
        {
            string key = subStatusCode ?? statusCode;
            if (string.IsNullOrEmpty(key))
                return "Unknown reason";

            return FailureReasonMap.TryGetValue(key, out string description) ? description : $"Status code: {key}";
        }

        private List<LogonEvent> DetectSuspiciousActivity(List<LogonEvent> logonEvents, List<LogonEvent> failedLogonEvents)
        {
            var suspiciousEvents = new List<LogonEvent>();

            try
            {
                // Check for multiple failed logon attempts for the same user
                var failedLogonGroups = failedLogonEvents
                    .GroupBy(e => new { e.Username, e.Domain })
                    .Where(g => g.Count() >= 3) // 3 or more failed attempts
                    .ToList();

                foreach (var group in failedLogonGroups)
                {
                    var latestEvent = group.OrderByDescending(e => e.Timestamp).First();
                    latestEvent.IsSuspicious = true;
                    latestEvent.SuspiciousReason = $"Multiple failed logon attempts ({group.Count()}) for this account";
                    suspiciousEvents.Add(latestEvent);
                }

                // Check for logons outside normal hours (between 11 PM and 5 AM)
                var afterHoursLogons = logonEvents
                    .Where(e => e.Timestamp.Hour >= 23 || e.Timestamp.Hour < 5)
                    .Where(e => e.LogonType.Contains("Interactive") || e.LogonType.Contains("RDP"))
                    .ToList();

                foreach (var logonEvent in afterHoursLogons)
                {
                    logonEvent.IsSuspicious = true;
                    logonEvent.SuspiciousReason = "Logon outside normal hours";
                    suspiciousEvents.Add(logonEvent);
                }

                // Check for RDP logons from unusual IP addresses
                // This is a simplified check - in a real system, you'd have a whitelist of known IPs
                var rdpLogons = logonEvents
                    .Where(e => e.LogonType.Contains("RDP") && !string.IsNullOrEmpty(e.IpAddress) && !e.IpAddress.StartsWith("192.168."))
                    .ToList();

                foreach (var logonEvent in rdpLogons)
                {
                    logonEvent.IsSuspicious = true;
                    logonEvent.SuspiciousReason = $"RDP logon from non-local IP address: {logonEvent.IpAddress}";
                    suspiciousEvents.Add(logonEvent);
                }

                // Check for account lockouts
                var lockouts = failedLogonEvents
                    .Where(e => e.EventType == "Account Lockout" || e.FailureReason.Contains("locked"))
                    .ToList();

                foreach (var lockoutEvent in lockouts)
                {
                    lockoutEvent.IsSuspicious = true;
                    lockoutEvent.SuspiciousReason = "Account locked out due to multiple failed attempts";
                    suspiciousEvents.Add(lockoutEvent);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error detecting suspicious activity");
            }

            return suspiciousEvents;
        }

        private void UpdateEventCollection(ObservableCollection<LogonEvent> collection, List<LogonEvent> newEvents)
        {
            // Add new events to the beginning of the collection
            foreach (var newEvent in newEvents.OrderByDescending(e => e.Timestamp))
            {
                collection.Insert(0, newEvent);
            }

            // Limit the collection size
            while (collection.Count > MaxEventsToRetrieve)
            {
                collection.RemoveAt(collection.Count - 1);
            }
        }

        private bool EventLogExists(string logName)
        {
            try
            {
                using (var eventLog = new EventLogReader(new EventLogQuery(logName, PathType.LogName)))
                {
                    return true;
                }
            }
            catch (EventLogNotFoundException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning($"Access denied to {logName} event log. Run the application as Administrator.");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error checking if event log {logName} exists");
                return false;
            }
        }
    }
}