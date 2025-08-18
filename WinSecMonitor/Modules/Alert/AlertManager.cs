using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Timers;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Alert
{
    /// <summary>
    /// Severity levels for alerts in the system
    /// </summary>
    public enum AlertSeverity
    {
        Low,
        Medium,
        High
    }

    /// <summary>
    /// Types of alerts that can be generated in the system
    /// </summary>
    public enum AlertType
    {
        // System alerts
        SystemPerformance,
        SystemConfiguration,
        SystemCrash,
        
        // User alerts
        UserAuthentication,
        UserPrivilegeChange,
        UserAccountModification,
        
        // Process alerts
        ProcessSuspicious,
        ProcessCrash,
        ProcessResourceUsage,
        
        // File/Registry alerts
        FileSystemChange,
        RegistryChange,
        MaliciousFile,
        
        // Network alerts
        NetworkConnection,
        NetworkTraffic,
        MaliciousIP,
        
        // Vulnerability alerts
        MissingPatch,
        SecurityPolicy,
        ComplianceViolation,
        
        // Event log alerts
        EventLogCorrelation,
        RootkitDetection,
        ThreatIntelligence,
        
        // Other
        Custom
    }

    /// <summary>
    /// Represents an alert in the system with all relevant information
    /// </summary>
    public class Alert
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public AlertSeverity Severity { get; set; }
        public AlertType Type { get; set; }
        public DateTime Timestamp { get; set; }
        public string Source { get; set; }
        public Dictionary<string, string> AdditionalData { get; set; }
        public bool Acknowledged { get; set; }
        public bool AutoMitigated { get; set; }
        public string MitigationAction { get; set; }
        public string MitigationResult { get; set; }

        public Alert()
        {
            Id = Guid.NewGuid();
            Timestamp = DateTime.Now;
            AdditionalData = new Dictionary<string, string>();
            Acknowledged = false;
            AutoMitigated = false;
        }
    }

    /// <summary>
    /// Event arguments for when a new alert is generated
    /// </summary>
    public class AlertGeneratedEventArgs : EventArgs
    {
        public Alert Alert { get; set; }

        public AlertGeneratedEventArgs(Alert alert)
        {
            Alert = alert;
        }
    }

    /// <summary>
    /// Event arguments for when an alert is acknowledged
    /// </summary>
    public class AlertAcknowledgedEventArgs : EventArgs
    {
        public Alert Alert { get; set; }

        public AlertAcknowledgedEventArgs(Alert alert)
        {
            Alert = alert;
        }
    }

    /// <summary>
    /// Event arguments for when an error occurs in the AlertManager
    /// </summary>
    public class AlertManagerErrorEventArgs : EventArgs
    {
        public string ErrorMessage { get; set; }
        public Exception Exception { get; set; }

        public AlertManagerErrorEventArgs(string errorMessage, Exception exception = null)
        {
            ErrorMessage = errorMessage;
            Exception = exception;
        }
    }

    /// <summary>
    /// Manages alerts from all monitoring modules, categorizes them, and provides access to the alert history
    /// </summary>
    public class AlertManager
    {
        private readonly object _alertLock = new object();
        private readonly Timer _cleanupTimer;
        private readonly int _maxAlertHistory;
        private readonly int _cleanupIntervalMinutes;

        // Alert collections
        private ObservableCollection<Alert> _alerts;
        public ReadOnlyObservableCollection<Alert> Alerts { get; private set; }

        // Alert statistics
        public int TotalAlerts { get; private set; }
        public int LowSeverityCount { get; private set; }
        public int MediumSeverityCount { get; private set; }
        public int HighSeverityCount { get; private set; }
        public int UnacknowledgedCount { get; private set; }
        public int AutoMitigatedCount { get; private set; }

        // Events
        public event EventHandler<AlertGeneratedEventArgs> AlertGenerated;
        public event EventHandler<AlertAcknowledgedEventArgs> AlertAcknowledged;
        public event EventHandler<AlertManagerErrorEventArgs> AlertManagerError;

        /// <summary>
        /// Initializes a new instance of the AlertManager class
        /// </summary>
        /// <param name="maxAlertHistory">Maximum number of alerts to keep in history</param>
        /// <param name="cleanupIntervalMinutes">Interval in minutes for cleaning up old alerts</param>
        public AlertManager(int maxAlertHistory = 1000, int cleanupIntervalMinutes = 60)
        {
            _maxAlertHistory = maxAlertHistory;
            _cleanupIntervalMinutes = cleanupIntervalMinutes;
            
            _alerts = new ObservableCollection<Alert>();
            Alerts = new ReadOnlyObservableCollection<Alert>(_alerts);
            
            // Initialize statistics
            TotalAlerts = 0;
            LowSeverityCount = 0;
            MediumSeverityCount = 0;
            HighSeverityCount = 0;
            UnacknowledgedCount = 0;
            AutoMitigatedCount = 0;

            // Setup cleanup timer
            _cleanupTimer = new Timer(_cleanupIntervalMinutes * 60 * 1000);
            _cleanupTimer.Elapsed += CleanupTimerElapsed;
            _cleanupTimer.AutoReset = true;
            _cleanupTimer.Start();
        }

        /// <summary>
        /// Adds a new alert to the system
        /// </summary>
        /// <param name="alert">The alert to add</param>
        public void AddAlert(Alert alert)
        {
            try
            {
                lock (_alertLock)
                {
                    // Add alert to collection
                    _alerts.Add(alert);
                    
                    // Update statistics
                    TotalAlerts++;
                    UpdateAlertStatistics(alert, true);
                    
                    // Cleanup if we exceed max history
                    if (_alerts.Count > _maxAlertHistory)
                    {
                        CleanupOldAlerts(_alerts.Count - _maxAlertHistory);
                    }
                }
                
                // Notify subscribers
                OnAlertGenerated(new AlertGeneratedEventArgs(alert));
                
                // Log the alert
                LogAlert(alert);
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error adding alert: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
        }

        /// <summary>
        /// Creates and adds a new alert to the system
        /// </summary>
        /// <param name="title">Alert title</param>
        /// <param name="description">Alert description</param>
        /// <param name="severity">Alert severity</param>
        /// <param name="type">Alert type</param>
        /// <param name="source">Source of the alert</param>
        /// <param name="additionalData">Any additional data for the alert</param>
        /// <returns>The created alert</returns>
        public Alert CreateAlert(string title, string description, AlertSeverity severity, 
            AlertType type, string source, Dictionary<string, string> additionalData = null)
        {
            try
            {
                var alert = new Alert
                {
                    Title = title,
                    Description = description,
                    Severity = severity,
                    Type = type,
                    Source = source,
                    AdditionalData = additionalData ?? new Dictionary<string, string>()
                };
                
                AddAlert(alert);
                return alert;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error creating alert: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return null;
            }
        }

        /// <summary>
        /// Acknowledges an alert
        /// </summary>
        /// <param name="alertId">ID of the alert to acknowledge</param>
        /// <returns>True if successful, false otherwise</returns>
        public bool AcknowledgeAlert(Guid alertId)
        {
            try
            {
                Alert alert = null;
                
                lock (_alertLock)
                {
                    alert = _alerts.FirstOrDefault(a => a.Id == alertId);
                    if (alert != null && !alert.Acknowledged)
                    {
                        alert.Acknowledged = true;
                        UnacknowledgedCount--;
                    }
                }
                
                if (alert != null && alert.Acknowledged)
                {
                    OnAlertAcknowledged(new AlertAcknowledgedEventArgs(alert));
                    Logger.Log($"Alert acknowledged: {alert.Id} - {alert.Title}");
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error acknowledging alert: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return false;
            }
        }

        /// <summary>
        /// Updates an alert with mitigation information
        /// </summary>
        /// <param name="alertId">ID of the alert</param>
        /// <param name="mitigationAction">Action taken to mitigate</param>
        /// <param name="mitigationResult">Result of the mitigation</param>
        /// <param name="autoMitigated">Whether it was automatically mitigated</param>
        /// <returns>True if successful, false otherwise</returns>
        public bool UpdateAlertMitigation(Guid alertId, string mitigationAction, string mitigationResult, bool autoMitigated)
        {
            try
            {
                lock (_alertLock)
                {
                    var alert = _alerts.FirstOrDefault(a => a.Id == alertId);
                    if (alert != null)
                    {
                        bool wasAutoMitigated = alert.AutoMitigated;
                        
                        alert.MitigationAction = mitigationAction;
                        alert.MitigationResult = mitigationResult;
                        alert.AutoMitigated = autoMitigated;
                        
                        // Update statistics if auto-mitigation status changed
                        if (autoMitigated && !wasAutoMitigated)
                        {
                            AutoMitigatedCount++;
                        }
                        else if (!autoMitigated && wasAutoMitigated)
                        {
                            AutoMitigatedCount--;
                        }
                        
                        Logger.Log($"Alert mitigation updated: {alert.Id} - {mitigationAction} - {mitigationResult}");
                        return true;
                    }
                    return false;
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error updating alert mitigation: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return false;
            }
        }

        /// <summary>
        /// Gets alerts filtered by various criteria
        /// </summary>
        /// <param name="severity">Filter by severity</param>
        /// <param name="type">Filter by type</param>
        /// <param name="source">Filter by source</param>
        /// <param name="onlyUnacknowledged">Only return unacknowledged alerts</param>
        /// <param name="onlyAutoMitigated">Only return auto-mitigated alerts</param>
        /// <param name="startTime">Filter by start time</param>
        /// <param name="endTime">Filter by end time</param>
        /// <returns>Collection of filtered alerts</returns>
        public IEnumerable<Alert> GetFilteredAlerts(
            AlertSeverity? severity = null,
            AlertType? type = null,
            string source = null,
            bool? onlyUnacknowledged = null,
            bool? onlyAutoMitigated = null,
            DateTime? startTime = null,
            DateTime? endTime = null)
        {
            try
            {
                lock (_alertLock)
                {
                    IEnumerable<Alert> filteredAlerts = _alerts.AsEnumerable();
                    
                    // Apply filters
                    if (severity.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Severity == severity.Value);
                    }
                    
                    if (type.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Type == type.Value);
                    }
                    
                    if (!string.IsNullOrEmpty(source))
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Source.Contains(source));
                    }
                    
                    if (onlyUnacknowledged.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Acknowledged == !onlyUnacknowledged.Value);
                    }
                    
                    if (onlyAutoMitigated.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.AutoMitigated == onlyAutoMitigated.Value);
                    }
                    
                    if (startTime.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Timestamp >= startTime.Value);
                    }
                    
                    if (endTime.HasValue)
                    {
                        filteredAlerts = filteredAlerts.Where(a => a.Timestamp <= endTime.Value);
                    }
                    
                    return filteredAlerts.ToList(); // Create a copy to avoid thread issues
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error filtering alerts: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return Enumerable.Empty<Alert>();
            }
        }

        /// <summary>
        /// Gets alerts by severity level
        /// </summary>
        /// <param name="severity">The severity level to filter by</param>
        /// <returns>Collection of alerts with the specified severity</returns>
        public IEnumerable<Alert> GetAlertsBySeverity(AlertSeverity severity)
        {
            return GetFilteredAlerts(severity: severity);
        }

        /// <summary>
        /// Gets unacknowledged alerts
        /// </summary>
        /// <returns>Collection of unacknowledged alerts</returns>
        public IEnumerable<Alert> GetUnacknowledgedAlerts()
        {
            return GetFilteredAlerts(onlyUnacknowledged: true);
        }

        /// <summary>
        /// Gets auto-mitigated alerts
        /// </summary>
        /// <returns>Collection of auto-mitigated alerts</returns>
        public IEnumerable<Alert> GetAutoMitigatedAlerts()
        {
            return GetFilteredAlerts(onlyAutoMitigated: true);
        }

        /// <summary>
        /// Gets recent alerts within a specified time window
        /// </summary>
        /// <param name="minutes">Time window in minutes</param>
        /// <returns>Collection of recent alerts</returns>
        public IEnumerable<Alert> GetRecentAlerts(int minutes = 60)
        {
            DateTime startTime = DateTime.Now.AddMinutes(-minutes);
            return GetFilteredAlerts(startTime: startTime);
        }

        /// <summary>
        /// Exports alerts to a string in CSV format
        /// </summary>
        /// <param name="alerts">Alerts to export</param>
        /// <returns>CSV formatted string</returns>
        public string ExportAlertsToCsv(IEnumerable<Alert> alerts)
        {
            try
            {
                var csv = new System.Text.StringBuilder();
                
                // Add header
                csv.AppendLine("Id,Title,Description,Severity,Type,Timestamp,Source,Acknowledged,AutoMitigated,MitigationAction,MitigationResult");
                
                // Add data rows
                foreach (var alert in alerts)
                {
                    csv.AppendLine($"\"{alert.Id}\",\"{EscapeCsvField(alert.Title)}\",\"{EscapeCsvField(alert.Description)}\",{alert.Severity},{alert.Type},\"{alert.Timestamp}\",\"{EscapeCsvField(alert.Source)}\",{alert.Acknowledged},{alert.AutoMitigated},\"{EscapeCsvField(alert.MitigationAction)}\",\"{EscapeCsvField(alert.MitigationResult)}\"");
                }
                
                return csv.ToString();
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error exporting alerts to CSV: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return string.Empty;
            }
        }

        /// <summary>
        /// Clears all acknowledged alerts
        /// </summary>
        /// <returns>Number of alerts cleared</returns>
        public int ClearAcknowledgedAlerts()
        {
            try
            {
                lock (_alertLock)
                {
                    var acknowledgedAlerts = _alerts.Where(a => a.Acknowledged).ToList();
                    int count = acknowledgedAlerts.Count;
                    
                    foreach (var alert in acknowledgedAlerts)
                    {
                        _alerts.Remove(alert);
                        UpdateAlertStatistics(alert, false);
                    }
                    
                    Logger.Log($"Cleared {count} acknowledged alerts");
                    return count;
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error clearing acknowledged alerts: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return 0;
            }
        }

        /// <summary>
        /// Clears all alerts older than a specified time
        /// </summary>
        /// <param name="olderThan">Time threshold</param>
        /// <returns>Number of alerts cleared</returns>
        public int ClearAlertsOlderThan(DateTime olderThan)
        {
            try
            {
                lock (_alertLock)
                {
                    var oldAlerts = _alerts.Where(a => a.Timestamp < olderThan).ToList();
                    int count = oldAlerts.Count;
                    
                    foreach (var alert in oldAlerts)
                    {
                        _alerts.Remove(alert);
                        UpdateAlertStatistics(alert, false);
                    }
                    
                    Logger.Log($"Cleared {count} alerts older than {olderThan}");
                    return count;
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error clearing old alerts: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return 0;
            }
        }

        /// <summary>
        /// Disposes resources used by the AlertManager
        /// </summary>
        public void Dispose()
        {
            _cleanupTimer.Stop();
            _cleanupTimer.Elapsed -= CleanupTimerElapsed;
            _cleanupTimer.Dispose();
        }

        #region Private Methods

        private void CleanupTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try
            {
                // Remove alerts older than 30 days by default
                ClearAlertsOlderThan(DateTime.Now.AddDays(-30));
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error in cleanup timer: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
        }

        private void CleanupOldAlerts(int count)
        {
            try
            {
                // Remove oldest alerts first
                var oldestAlerts = _alerts.OrderBy(a => a.Timestamp).Take(count).ToList();
                
                foreach (var alert in oldestAlerts)
                {
                    _alerts.Remove(alert);
                    UpdateAlertStatistics(alert, false);
                }
                
                Logger.Log($"Cleaned up {count} old alerts due to max history limit");
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error cleaning up old alerts: {ex.Message}";
                OnAlertManagerError(new AlertManagerErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
        }

        private void UpdateAlertStatistics(Alert alert, bool isAdding)
        {
            int modifier = isAdding ? 1 : -1;
            
            // Update severity counts
            switch (alert.Severity)
            {
                case AlertSeverity.Low:
                    LowSeverityCount += modifier;
                    break;
                case AlertSeverity.Medium:
                    MediumSeverityCount += modifier;
                    break;
                case AlertSeverity.High:
                    HighSeverityCount += modifier;
                    break;
            }
            
            // Update other counts
            if (!alert.Acknowledged)
            {
                UnacknowledgedCount += modifier;
            }
            
            if (alert.AutoMitigated)
            {
                AutoMitigatedCount += modifier;
            }
        }

        private void LogAlert(Alert alert)
        {
            string logMessage = $"Alert: [{alert.Severity}] {alert.Title} - {alert.Description} (Source: {alert.Source})";
            
            switch (alert.Severity)
            {
                case AlertSeverity.High:
                    Logger.LogError(logMessage);
                    break;
                case AlertSeverity.Medium:
                    Logger.LogWarning(logMessage);
                    break;
                default:
                    Logger.Log(logMessage);
                    break;
            }
        }

        private string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
            {
                return string.Empty;
            }
            
            // Replace double quotes with two double quotes
            return field.Replace("\"", "\"\"");
        }

        #endregion

        #region Event Handlers

        protected virtual void OnAlertGenerated(AlertGeneratedEventArgs e)
        {
            AlertGenerated?.Invoke(this, e);
        }

        protected virtual void OnAlertAcknowledged(AlertAcknowledgedEventArgs e)
        {
            AlertAcknowledged?.Invoke(this, e);
        }

        protected virtual void OnAlertManagerError(AlertManagerErrorEventArgs e)
        {
            AlertManagerError?.Invoke(this, e);
        }

        #endregion
    }
}