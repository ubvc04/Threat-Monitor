using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Media;
using System.Threading.Tasks;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.User
{
    public class SecurityAlert
    {   
        public DateTime Timestamp { get; set; }
        public string AlertType { get; set; }  // Authentication, RDP, Privilege
        public string Source { get; set; }     // Component that generated the alert
        public string Username { get; set; }
        public string Description { get; set; }
        public string Details { get; set; }
        public AlertSeverity Severity { get; set; }
        public bool IsAcknowledged { get; set; }
        public DateTime? AcknowledgedTime { get; set; }
        public string AcknowledgedBy { get; set; }

        public string FormattedTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
        public string FormattedSeverity => Severity.ToString();
        public string Status => IsAcknowledged ? $"Acknowledged by {AcknowledgedBy} at {AcknowledgedTime?.ToString("yyyy-MM-dd HH:mm:ss")}" : "Unacknowledged";
    }

    public enum AlertSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class AlertGenerator
    {
        private readonly Logger _logger;
        private readonly Dispatcher _dispatcher;
        private readonly AuthenticationMonitor _authMonitor;
        private readonly RDPSessionMonitor _rdpMonitor;
        private readonly PrivilegeMonitor _privilegeMonitor;
        private readonly SoundPlayer _alertSound;
        private readonly Dictionary<string, DateTime> _alertThrottling;
        private readonly TimeSpan _throttleWindow = TimeSpan.FromMinutes(15);

        public ObservableCollection<SecurityAlert> ActiveAlerts { get; private set; }
        public ObservableCollection<SecurityAlert> AlertHistory { get; private set; }

        public event EventHandler<SecurityAlert> NewAlertGenerated;

        public AlertGenerator(AuthenticationMonitor authMonitor, RDPSessionMonitor rdpMonitor, 
                             PrivilegeMonitor privilegeMonitor, Dispatcher dispatcher = null)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;
            _authMonitor = authMonitor;
            _rdpMonitor = rdpMonitor;
            _privilegeMonitor = privilegeMonitor;
            _alertThrottling = new Dictionary<string, DateTime>();

            ActiveAlerts = new ObservableCollection<SecurityAlert>();
            AlertHistory = new ObservableCollection<SecurityAlert>();

            // Initialize sound player for alerts
            try
            {
                _alertSound = new SoundPlayer(System.IO.Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory, "Resources", "alert.wav"));
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing alert sound");
                _alertSound = null;
            }

            // Subscribe to suspicious activity events
            if (_authMonitor != null)
            {
                _authMonitor.SuspiciousActivityDetected += AuthMonitor_SuspiciousActivityDetected;
            }

            if (_rdpMonitor != null)
            {
                _rdpMonitor.SuspiciousRDPActivityDetected += RdpMonitor_SuspiciousRDPActivityDetected;
            }

            if (_privilegeMonitor != null)
            {
                _privilegeMonitor.SuspiciousActivityDetected += PrivilegeMonitor_SuspiciousActivityDetected;
            }
        }

        private void AuthMonitor_SuspiciousActivityDetected(object sender, EventArgs e)
        {
            try
            {
                if (_authMonitor.SuspiciousEvents.Count > 0)
                {
                    foreach (var suspiciousEvent in _authMonitor.SuspiciousEvents.Take(10))
                    {
                        // Check if we've already alerted about this type of event for this user recently
                        string alertKey = $"Auth_{suspiciousEvent.Username}_{suspiciousEvent.SuspiciousReason}";
                        if (ShouldThrottleAlert(alertKey))
                            continue;

                        // Determine severity based on the type of suspicious activity
                        var severity = AlertSeverity.Medium;
                        if (suspiciousEvent.SuspiciousReason.Contains("Multiple failed") || 
                            suspiciousEvent.SuspiciousReason.Contains("locked"))
                        {
                            severity = AlertSeverity.High;
                        }

                        var alert = new SecurityAlert
                        {
                            Timestamp = DateTime.Now,
                            AlertType = "Authentication",
                            Source = "Authentication Monitor",
                            Username = suspiciousEvent.Username,
                            Description = suspiciousEvent.SuspiciousReason,
                            Details = $"Event Type: {suspiciousEvent.EventType}\n" +
                                     $"Time: {suspiciousEvent.FormattedTimestamp}\n" +
                                     $"User: {suspiciousEvent.Username}\n" +
                                     $"Domain: {suspiciousEvent.Domain}\n" +
                                     $"Workstation: {suspiciousEvent.WorkstationName}\n" +
                                     $"IP Address: {suspiciousEvent.IpAddress}\n" +
                                     $"Logon Type: {suspiciousEvent.LogonType}",
                            Severity = severity,
                            IsAcknowledged = false
                        };

                        GenerateAlert(alert);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error generating authentication alerts");
            }
        }

        private void RdpMonitor_SuspiciousRDPActivityDetected(object sender, EventArgs e)
        {
            try
            {
                if (_rdpMonitor.SuspiciousSessions.Count > 0)
                {
                    foreach (var suspiciousSession in _rdpMonitor.SuspiciousSessions.Take(10))
                    {
                        // Check if we've already alerted about this type of event for this user recently
                        string alertKey = $"RDP_{suspiciousSession.Username}_{suspiciousSession.SuspiciousReason}";
                        if (ShouldThrottleAlert(alertKey))
                            continue;

                        // Determine severity based on the type of suspicious activity
                        var severity = AlertSeverity.Medium;
                        if (suspiciousSession.SuspiciousReason.Contains("unknown IP") || 
                            suspiciousSession.SuspiciousReason.Contains("outside the local network"))
                        {
                            severity = AlertSeverity.High;
                        }

                        var alert = new SecurityAlert
                        {
                            Timestamp = DateTime.Now,
                            AlertType = "RDP",
                            Source = "RDP Session Monitor",
                            Username = suspiciousSession.Username,
                            Description = suspiciousSession.SuspiciousReason,
                            Details = $"User: {suspiciousSession.Username}\n" +
                                     $"Client Name: {suspiciousSession.ClientName}\n" +
                                     $"Client Address: {suspiciousSession.ClientAddress}\n" +
                                     $"Connect Time: {suspiciousSession.FormattedConnectTime}\n" +
                                     $"Session State: {suspiciousSession.SessionState}",
                            Severity = severity,
                            IsAcknowledged = false
                        };

                        GenerateAlert(alert);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error generating RDP alerts");
            }
        }

        private void PrivilegeMonitor_SuspiciousActivityDetected(object sender, EventArgs e)
        {
            try
            {
                if (_privilegeMonitor.SuspiciousEvents.Count > 0)
                {
                    foreach (var suspiciousEvent in _privilegeMonitor.SuspiciousEvents.Take(10))
                    {
                        // Check if we've already alerted about this type of event for this user recently
                        string alertKey = $"Priv_{suspiciousEvent.Username}_{suspiciousEvent.SuspiciousReason}";
                        if (ShouldThrottleAlert(alertKey))
                            continue;

                        // Determine severity based on the type of suspicious activity
                        var severity = AlertSeverity.Medium;
                        if (suspiciousEvent.SuspiciousReason.Contains("sensitive"))
                        {
                            severity = AlertSeverity.High;
                        }

                        var alert = new SecurityAlert
                        {
                            Timestamp = DateTime.Now,
                            AlertType = "Privilege",
                            Source = "Privilege Monitor",
                            Username = suspiciousEvent.Username,
                            Description = suspiciousEvent.SuspiciousReason,
                            Details = $"Event Type: {suspiciousEvent.EventType}\n" +
                                     $"Time: {suspiciousEvent.FormattedTimestamp}\n" +
                                     $"User: {suspiciousEvent.Username}\n" +
                                     $"Domain: {suspiciousEvent.Domain}\n" +
                                     $"Process: {suspiciousEvent.ProcessName}\n" +
                                     $"Privilege/Group: {suspiciousEvent.PrivilegeName ?? suspiciousEvent.GroupName}\n" +
                                     $"Action: {suspiciousEvent.Action}",
                            Severity = severity,
                            IsAcknowledged = false
                        };

                        GenerateAlert(alert);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error generating privilege alerts");
            }
        }

        private void GenerateAlert(SecurityAlert alert)
        {
            try
            {
                _logger.LogWarning($"Security Alert: {alert.Description} - {alert.Username}");

                // Update collections on the UI thread if dispatcher is available
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        ActiveAlerts.Insert(0, alert);
                        AlertHistory.Insert(0, alert);
                        
                        // Limit the number of alerts to keep
                        while (AlertHistory.Count > 1000)
                        {
                            AlertHistory.RemoveAt(AlertHistory.Count - 1);
                        }
                        
                        NewAlertGenerated?.Invoke(this, alert);
                    });
                }
                else
                {
                    ActiveAlerts.Insert(0, alert);
                    AlertHistory.Insert(0, alert);
                    
                    // Limit the number of alerts to keep
                    while (AlertHistory.Count > 1000)
                    {
                        AlertHistory.RemoveAt(AlertHistory.Count - 1);
                    }
                    
                    NewAlertGenerated?.Invoke(this, alert);
                }

                // Play alert sound for high and critical alerts
                if ((alert.Severity == AlertSeverity.High || alert.Severity == AlertSeverity.Critical) && _alertSound != null)
                {
                    Task.Run(() => {
                        try
                        {
                            _alertSound.Play();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogException(ex, "Error playing alert sound");
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error generating alert");
            }
        }

        public void AcknowledgeAlert(SecurityAlert alert, string acknowledgedBy)
        {
            try
            {
                if (alert != null && !alert.IsAcknowledged)
                {
                    alert.IsAcknowledged = true;
                    alert.AcknowledgedTime = DateTime.Now;
                    alert.AcknowledgedBy = acknowledgedBy;

                    _logger.LogInformation($"Alert acknowledged: {alert.Description} by {acknowledgedBy}");

                    // Remove from active alerts
                    if (_dispatcher != null)
                    {
                        _dispatcher.Invoke(() =>
                        {
                            if (ActiveAlerts.Contains(alert))
                            {
                                ActiveAlerts.Remove(alert);
                            }
                        });
                    }
                    else
                    {
                        if (ActiveAlerts.Contains(alert))
                        {
                            ActiveAlerts.Remove(alert);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging alert");
            }
        }

        public void AcknowledgeAllAlerts(string acknowledgedBy)
        {
            try
            {
                var alertsToAcknowledge = ActiveAlerts.ToList();
                foreach (var alert in alertsToAcknowledge)
                {
                    AcknowledgeAlert(alert, acknowledgedBy);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging all alerts");
            }
        }

        private bool ShouldThrottleAlert(string alertKey)
        {
            // Check if we've already alerted about this type of event recently
            if (_alertThrottling.TryGetValue(alertKey, out DateTime lastAlertTime))
            {
                if (DateTime.Now - lastAlertTime < _throttleWindow)
                {
                    // We've already alerted about this recently, so throttle it
                    return true;
                }
            }

            // Update the last alert time for this key
            _alertThrottling[alertKey] = DateTime.Now;
            return false;
        }

        public void ClearAlertHistory()
        {
            try
            {
                if (_dispatcher != null)
                {
                    _dispatcher.Invoke(() =>
                    {
                        AlertHistory.Clear();
                    });
                }
                else
                {
                    AlertHistory.Clear();
                }

                _logger.LogInformation("Alert history cleared");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error clearing alert history");
            }
        }
    }
}