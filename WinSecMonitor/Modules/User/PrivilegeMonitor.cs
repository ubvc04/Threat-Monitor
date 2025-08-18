using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.User
{
    public class PrivilegeEvent
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }  // Privilege Use, Special Privileges, Group Membership Change
        public string Username { get; set; }
        public string Domain { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string PrivilegeName { get; set; }
        public string GroupName { get; set; }
        public string Action { get; set; }  // Added, Removed, Used
        public int EventId { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspiciousReason { get; set; }

        public string FormattedTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
        public string FormattedEventType => $"{EventType} ({EventId})";
    }

    public class UserPrivilegeInfo
    {
        public string Username { get; set; }
        public string Domain { get; set; }
        public string Sid { get; set; }
        public List<string> Groups { get; set; } = new List<string>();
        public List<string> Privileges { get; set; } = new List<string>();
        public bool IsAdministrator { get; set; }
        public bool IsInAdminGroup { get; set; }
        public DateTime LastUpdated { get; set; }

        public string FullUsername => string.IsNullOrEmpty(Domain) ? Username : $"{Domain}\\{Username}";
    }

    public class PrivilegeMonitor
    {
        private readonly Logger _logger;
        private readonly Timer _refreshTimer;
        private readonly Dispatcher _dispatcher;
        private DateTime _lastEventTime;
        private const string SecurityLogName = "Security";
        private const int MaxEventsToRetrieve = 100;

        // Event IDs for privilege-related events
        private static readonly int[] PrivilegeUseEventIds = { 4673, 4674 };           // Privilege Use
        private static readonly int[] SpecialPrivilegeEventIds = { 4672 };             // Special Logon (Admin)
        private static readonly int[] GroupMembershipChangeEventIds = { 4728, 4729, 4732, 4733, 4756, 4757 }; // Group changes
        private static readonly int[] UserAccountChangeEventIds = { 4720, 4722, 4724, 4738 }; // User account changes
        private static readonly int[] ProcessElevationEventIds = { 4688 };              // Process creation with elevation

        // List of sensitive privileges to monitor
        private static readonly List<string> SensitivePrivileges = new List<string>
        {
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeTcbPrivilege",
            "SeSecurityPrivilege"
        };

        // List of sensitive groups to monitor
        private static readonly List<string> SensitiveGroups = new List<string>
        {
            "Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Backup Operators",
            "Account Operators",
            "Server Operators",
            "Print Operators",
            "Remote Desktop Users"
        };

        public ObservableCollection<PrivilegeEvent> RecentPrivilegeEvents { get; private set; }
        public ObservableCollection<UserPrivilegeInfo> UserPrivileges { get; private set; }
        public ObservableCollection<PrivilegeEvent> SuspiciousEvents { get; private set; }

        public event EventHandler PrivilegeEventsUpdated;
        public event EventHandler SuspiciousActivityDetected;

        public PrivilegeMonitor(Dispatcher dispatcher = null)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;
            _lastEventTime = DateTime.Now.AddHours(-1); // Start by getting events from the last hour

            RecentPrivilegeEvents = new ObservableCollection<PrivilegeEvent>();
            UserPrivileges = new ObservableCollection<UserPrivilegeInfo>();
            SuspiciousEvents = new ObservableCollection<PrivilegeEvent>();

            // Set up timer for periodic refresh (every 60 seconds)
            _refreshTimer = new Timer(60000);
            _refreshTimer.Elapsed += async (s, e) => await RefreshEventsAsync();
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogDebug("Initializing PrivilegeMonitor");
                await RefreshEventsAsync();
                await RefreshUserPrivilegesAsync();
                _logger.LogInformation("PrivilegeMonitor initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing PrivilegeMonitor");
            }
        }

        public void StartMonitoring()
        {
            try
            {
                _logger.LogDebug("Starting privilege monitoring");
                _refreshTimer.Start();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error starting privilege monitoring");
            }
        }

        public void StopMonitoring()
        {
            try
            {
                _logger.LogDebug("Stopping privilege monitoring");
                _refreshTimer.Stop();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error stopping privilege monitoring");
            }
        }

        public async Task RefreshEventsAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing privilege events");

                // Check if Security log is accessible
                if (!EventLogExists(SecurityLogName))
                {
                    _logger.LogWarning($"Security event log is not accessible. This may be due to insufficient permissions.");
                    return;
                }

                var newEvents = await Task.Run(() => GetPrivilegeEvents());

                // Update the last event time to the most recent event
                if (newEvents.Any())
                {
                    _lastEventTime = newEvents.Max(e => e.Timestamp);
                }

                // Check for suspicious activity
                var suspiciousEvents = DetectSuspiciousPrivilegeActivity(newEvents);

                // Update collections on the UI thread if dispatcher is available
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        UpdateEventCollection(RecentPrivilegeEvents, newEvents);
                        
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
                        
                        PrivilegeEventsUpdated?.Invoke(this, EventArgs.Empty);
                    });
                }
                else
                {
                    UpdateEventCollection(RecentPrivilegeEvents, newEvents);
                    
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
                    
                    PrivilegeEventsUpdated?.Invoke(this, EventArgs.Empty);
                }

                // Refresh user privileges if we detected any group membership changes
                if (newEvents.Any(e => GroupMembershipChangeEventIds.Contains(e.EventId) || UserAccountChangeEventIds.Contains(e.EventId)))
                {
                    await RefreshUserPrivilegesAsync();
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogException(ex, "Access denied to Security event log. Run the application as Administrator.");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing privilege events");
            }
        }

        public async Task RefreshUserPrivilegesAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing user privileges");

                var userPrivileges = await Task.Run(() => GetUserPrivileges());

                // Update collection on the UI thread if dispatcher is available
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        UpdateUserPrivilegeCollection(userPrivileges);
                    });
                }
                else
                {
                    UpdateUserPrivilegeCollection(userPrivileges);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing user privileges");
            }
        }

        private List<PrivilegeEvent> GetPrivilegeEvents()
        {
            var events = new List<PrivilegeEvent>();

            try
            {
                // Query for privilege use events
                string privilegeUseQuery = CreateEventQuery(PrivilegeUseEventIds);
                events.AddRange(QueryEvents(privilegeUseQuery, "Privilege Use"));

                // Query for special privilege events
                string specialPrivilegeQuery = CreateEventQuery(SpecialPrivilegeEventIds);
                events.AddRange(QueryEvents(specialPrivilegeQuery, "Special Privileges"));

                // Query for group membership change events
                string groupMembershipQuery = CreateEventQuery(GroupMembershipChangeEventIds);
                events.AddRange(QueryEvents(groupMembershipQuery, "Group Membership Change"));

                // Query for process elevation events
                string processElevationQuery = CreateEventQuery(ProcessElevationEventIds);
                events.AddRange(QueryEvents(processElevationQuery, "Process Elevation"));
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error retrieving privilege events");
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

        private List<PrivilegeEvent> QueryEvents(string query, string eventType)
        {
            var events = new List<PrivilegeEvent>();

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
                            var privilegeEvent = ParseEventRecord(eventRecord, eventType);
                            if (privilegeEvent != null)
                            {
                                events.Add(privilegeEvent);
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

        private PrivilegeEvent ParseEventRecord(EventRecord eventRecord, string eventType)
        {
            try
            {
                var privilegeEvent = new PrivilegeEvent
                {
                    Timestamp = eventRecord.TimeCreated ?? DateTime.Now,
                    EventType = eventType,
                    EventId = eventRecord.Id
                };

                // Extract event-specific properties based on event ID
                switch (eventRecord.Id)
                {
                    case 4672: // Special privileges assigned to new logon
                        ExtractSpecialPrivilegeProperties(eventRecord, privilegeEvent);
                        break;
                    case 4673: // Sensitive privilege use
                    case 4674: // An operation was attempted on a privileged object
                        ExtractPrivilegeUseProperties(eventRecord, privilegeEvent);
                        break;
                    case 4728: // Member added to security-enabled global group
                    case 4732: // Member added to security-enabled local group
                    case 4756: // Member added to security-enabled universal group
                        ExtractGroupMembershipAddProperties(eventRecord, privilegeEvent);
                        break;
                    case 4729: // Member removed from security-enabled global group
                    case 4733: // Member removed from security-enabled local group
                    case 4757: // Member removed from security-enabled universal group
                        ExtractGroupMembershipRemoveProperties(eventRecord, privilegeEvent);
                        break;
                    case 4688: // A new process has been created
                        ExtractProcessElevationProperties(eventRecord, privilegeEvent);
                        break;
                }

                return privilegeEvent;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error parsing event record ID {eventRecord.Id}");
                return null;
            }
        }

        private void ExtractSpecialPrivilegeProperties(EventRecord eventRecord, PrivilegeEvent privilegeEvent)
        {
            if (eventRecord.Properties.Count >= 2)
            {
                privilegeEvent.Username = eventRecord.Properties[1].Value?.ToString();
                privilegeEvent.Domain = eventRecord.Properties[2].Value?.ToString();
                privilegeEvent.Action = "Assigned";
                privilegeEvent.PrivilegeName = "Special Privileges (Admin)";
            }
        }

        private void ExtractPrivilegeUseProperties(EventRecord eventRecord, PrivilegeEvent privilegeEvent)
        {
            if (eventRecord.Properties.Count >= 8)
            {
                privilegeEvent.Username = eventRecord.Properties[1].Value?.ToString();
                privilegeEvent.Domain = eventRecord.Properties[2].Value?.ToString();
                privilegeEvent.PrivilegeName = eventRecord.Properties[7].Value?.ToString();
                privilegeEvent.ProcessName = eventRecord.Properties[4].Value?.ToString();
                privilegeEvent.ProcessId = Convert.ToInt32(eventRecord.Properties[5].Value?.ToString() ?? "0");
                privilegeEvent.Action = "Used";
            }
        }

        private void ExtractGroupMembershipAddProperties(EventRecord eventRecord, PrivilegeEvent privilegeEvent)
        {
            if (eventRecord.Properties.Count >= 6)
            {
                privilegeEvent.Username = eventRecord.Properties[0].Value?.ToString(); // User who made the change
                privilegeEvent.Domain = eventRecord.Properties[1].Value?.ToString();
                privilegeEvent.GroupName = eventRecord.Properties[2].Value?.ToString(); // Group name
                privilegeEvent.Action = "Added to group";
            }
        }

        private void ExtractGroupMembershipRemoveProperties(EventRecord eventRecord, PrivilegeEvent privilegeEvent)
        {
            if (eventRecord.Properties.Count >= 6)
            {
                privilegeEvent.Username = eventRecord.Properties[0].Value?.ToString(); // User who made the change
                privilegeEvent.Domain = eventRecord.Properties[1].Value?.ToString();
                privilegeEvent.GroupName = eventRecord.Properties[2].Value?.ToString(); // Group name
                privilegeEvent.Action = "Removed from group";
            }
        }

        private void ExtractProcessElevationProperties(EventRecord eventRecord, PrivilegeEvent privilegeEvent)
        {
            if (eventRecord.Properties.Count >= 8)
            {
                privilegeEvent.Username = eventRecord.Properties[1].Value?.ToString();
                privilegeEvent.Domain = eventRecord.Properties[2].Value?.ToString();
                privilegeEvent.ProcessName = eventRecord.Properties[5].Value?.ToString();
                privilegeEvent.ProcessId = Convert.ToInt32(eventRecord.Properties[4].Value?.ToString() ?? "0");
                privilegeEvent.Action = "Process Created";

                // Check if this is an elevated process (requires additional parsing)
                // In a real implementation, you would check the TokenElevationType
                privilegeEvent.PrivilegeName = "Process Elevation";
            }
        }

        private List<UserPrivilegeInfo> GetUserPrivileges()
        {
            var userPrivileges = new List<UserPrivilegeInfo>();

            try
            {
                // Get all user accounts using WMI
                using (var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2", 
                    "SELECT * FROM Win32_UserAccount WHERE LocalAccount = True"))
                {
                    foreach (var userAccount in searcher.Get())
                    {
                        try
                        {
                            string username = userAccount["Name"]?.ToString();
                            string domain = userAccount["Domain"]?.ToString();
                            string sid = userAccount["SID"]?.ToString();

                            if (!string.IsNullOrEmpty(username))
                            {
                                var userInfo = new UserPrivilegeInfo
                                {
                                    Username = username,
                                    Domain = domain,
                                    Sid = sid,
                                    LastUpdated = DateTime.Now
                                };

                                // Get group memberships for this user
                                userInfo.Groups = GetUserGroups(username);
                                
                                // Check if user is in Administrators group
                                userInfo.IsInAdminGroup = userInfo.Groups.Any(g => 
                                    g.Equals("Administrators", StringComparison.OrdinalIgnoreCase) || 
                                    g.Equals("Domain Admins", StringComparison.OrdinalIgnoreCase));

                                // Add to the list
                                userPrivileges.Add(userInfo);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogException(ex, "Error processing user account WMI object");
                        }
                    }
                }

                // Get the current user's privileges
                var currentUserInfo = GetCurrentUserPrivileges();
                if (currentUserInfo != null)
                {
                    // Check if this user is already in our list
                    var existingUser = userPrivileges.FirstOrDefault(u => 
                        u.Username.Equals(currentUserInfo.Username, StringComparison.OrdinalIgnoreCase) && 
                        u.Domain.Equals(currentUserInfo.Domain, StringComparison.OrdinalIgnoreCase));

                    if (existingUser != null)
                    {
                        // Update existing user with privileges
                        existingUser.Privileges = currentUserInfo.Privileges;
                        existingUser.IsAdministrator = currentUserInfo.IsAdministrator;
                    }
                    else
                    {
                        // Add current user to the list
                        userPrivileges.Add(currentUserInfo);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting user privileges");
            }

            return userPrivileges;
        }

        private List<string> GetUserGroups(string username)
        {
            var groups = new List<string>();

            try
            {
                // Query for user group memberships using WMI
                using (var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2", 
                    $"SELECT * FROM Win32_GroupUser WHERE PartComponent LIKE '%{username}%'"))
                {
                    foreach (var groupUser in searcher.Get())
                    {
                        try
                        {
                            string groupPath = groupUser["GroupComponent"]?.ToString();
                            if (!string.IsNullOrEmpty(groupPath))
                            {
                                // Extract group name from the path
                                // Format is typically: "Win32_Group.Domain="DOMAIN",Name="GroupName""
                                int nameIndex = groupPath.IndexOf("Name=\"");
                                if (nameIndex >= 0)
                                {
                                    nameIndex += 6; // Length of "Name=""
                                    int endIndex = groupPath.IndexOf('"', nameIndex);
                                    if (endIndex > nameIndex)
                                    {
                                        string groupName = groupPath.Substring(nameIndex, endIndex - nameIndex);
                                        groups.Add(groupName);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogException(ex, "Error processing group user WMI object");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error getting groups for user {username}");
            }

            return groups;
        }

        private UserPrivilegeInfo GetCurrentUserPrivileges()
        {
            try
            {
                // Get current Windows identity
                var identity = WindowsIdentity.GetCurrent();
                if (identity != null)
                {
                    var userInfo = new UserPrivilegeInfo
                    {
                        Username = identity.Name.Split('\\').Last(),
                        Domain = identity.Name.Contains("\\") ? identity.Name.Split('\\')[0] : Environment.MachineName,
                        Sid = identity.User?.Value,
                        LastUpdated = DateTime.Now
                    };

                    // Check if user is administrator
                    var principal = new WindowsPrincipal(identity);
                    userInfo.IsAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator);

                    // Get group memberships
                    foreach (var group in identity.Groups)
                    {
                        try
                        {
                            var groupName = group.Translate(typeof(NTAccount)).Value;
                            if (!string.IsNullOrEmpty(groupName) && groupName.Contains("\\"))
                            {
                                userInfo.Groups.Add(groupName.Split('\\').Last());
                            }
                        }
                        catch
                        {
                            // Some SIDs cannot be translated to account names
                        }
                    }

                    // Check if user is in admin group
                    userInfo.IsInAdminGroup = userInfo.Groups.Any(g => 
                        g.Equals("Administrators", StringComparison.OrdinalIgnoreCase) || 
                        g.Equals("Domain Admins", StringComparison.OrdinalIgnoreCase));

                    // In a real implementation, you would also get the user's privileges
                    // This requires P/Invoke to Windows API functions like GetTokenInformation
                    // For demonstration, we'll just add some sample privileges
                    userInfo.Privileges = new List<string>
                    {
                        "SeChangeNotifyPrivilege",
                        "SeShutdownPrivilege",
                        "SeUndockPrivilege",
                        "SeIncreaseWorkingSetPrivilege",
                        "SeTimeZonePrivilege"
                    };

                    // Add admin privileges if the user is an administrator
                    if (userInfo.IsAdministrator || userInfo.IsInAdminGroup)
                    {
                        userInfo.Privileges.AddRange(new[]
                        {
                            "SeBackupPrivilege",
                            "SeDebugPrivilege",
                            "SeLoadDriverPrivilege",
                            "SeRestorePrivilege",
                            "SeSystemtimePrivilege",
                            "SeTakeOwnershipPrivilege"
                        });
                    }

                    return userInfo;
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting current user privileges");
            }

            return null;
        }

        private List<PrivilegeEvent> DetectSuspiciousPrivilegeActivity(List<PrivilegeEvent> events)
        {
            var suspiciousEvents = new List<PrivilegeEvent>();

            try
            {
                // Check for sensitive privilege use
                foreach (var evt in events.Where(e => e.EventType == "Privilege Use"))
                {
                    if (SensitivePrivileges.Any(p => evt.PrivilegeName?.Contains(p) == true))
                    {
                        evt.IsSuspicious = true;
                        evt.SuspiciousReason = $"Use of sensitive privilege: {evt.PrivilegeName}";
                        suspiciousEvents.Add(evt);
                    }
                }

                // Check for changes to sensitive groups
                foreach (var evt in events.Where(e => e.EventType == "Group Membership Change"))
                {
                    if (SensitiveGroups.Any(g => evt.GroupName?.Contains(g) == true))
                    {
                        evt.IsSuspicious = true;
                        evt.SuspiciousReason = $"Modification to sensitive group: {evt.GroupName}";
                        suspiciousEvents.Add(evt);
                    }
                }

                // Check for process elevation events from non-standard processes
                foreach (var evt in events.Where(e => e.EventType == "Process Elevation"))
                {
                    // Check if the process name is unusual for elevation
                    // This is a simplified check - in a real system, you'd have a whitelist
                    if (!string.IsNullOrEmpty(evt.ProcessName) && 
                        !evt.ProcessName.Contains("mmc.exe") && 
                        !evt.ProcessName.Contains("explorer.exe") && 
                        !evt.ProcessName.Contains("control.exe") &&
                        !evt.ProcessName.Contains("cmd.exe") &&
                        !evt.ProcessName.Contains("powershell.exe") &&
                        !evt.ProcessName.Contains("consent.exe"))
                    {
                        evt.IsSuspicious = true;
                        evt.SuspiciousReason = $"Unusual process elevation: {evt.ProcessName}";
                        suspiciousEvents.Add(evt);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error detecting suspicious privilege activity");
            }

            return suspiciousEvents;
        }

        private void UpdateEventCollection(ObservableCollection<PrivilegeEvent> collection, List<PrivilegeEvent> newEvents)
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

        private void UpdateUserPrivilegeCollection(List<UserPrivilegeInfo> newUserPrivileges)
        {
            // Update existing users and add new ones
            foreach (var newUserInfo in newUserPrivileges)
            {
                var existingUser = UserPrivileges.FirstOrDefault(u => 
                    u.Username.Equals(newUserInfo.Username, StringComparison.OrdinalIgnoreCase) && 
                    u.Domain.Equals(newUserInfo.Domain, StringComparison.OrdinalIgnoreCase));

                if (existingUser != null)
                {
                    // Update existing user
                    existingUser.Groups = newUserInfo.Groups;
                    existingUser.Privileges = newUserInfo.Privileges;
                    existingUser.IsAdministrator = newUserInfo.IsAdministrator;
                    existingUser.IsInAdminGroup = newUserInfo.IsInAdminGroup;
                    existingUser.LastUpdated = newUserInfo.LastUpdated;
                }
                else
                {
                    // Add new user
                    UserPrivileges.Add(newUserInfo);
                }
            }

            // Remove users that no longer exist
            for (int i = UserPrivileges.Count - 1; i >= 0; i--)
            {
                if (!newUserPrivileges.Any(u => 
                    u.Username.Equals(UserPrivileges[i].Username, StringComparison.OrdinalIgnoreCase) && 
                    u.Domain.Equals(UserPrivileges[i].Domain, StringComparison.OrdinalIgnoreCase)))
                {
                    UserPrivileges.RemoveAt(i);
                }
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