using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WinSecMonitor.Modules.Authentication;
using WinSecMonitor.Modules.EventLog;
using WinSecMonitor.Modules.FileRegistry;
using WinSecMonitor.Modules.Network;
using WinSecMonitor.Modules.Process;
using WinSecMonitor.Modules.System;
using WinSecMonitor.Modules.Vulnerability;

namespace WinSecMonitor.Modules.Alert
{
    /// <summary>
    /// Manages the integration between the Alert & Mitigation Engine and all other monitoring modules.
    /// Subscribes to events from each module and converts them to alerts when appropriate.
    /// </summary>
    public class AlertIntegrationManager
    {
        private readonly AlertManager _alertManager;
        private readonly MitigationEngine _mitigationEngine;
        private readonly ILogger _logger;

        // Module references
        private SystemMonitor _systemMonitor;
        private AuthenticationMonitor _authenticationMonitor;
        private FileRegistryMonitor _fileRegistryMonitor;
        private ProcessMonitor _processMonitor;
        private NetworkMonitor _networkMonitor;
        private VulnerabilityScanner _vulnerabilityScanner;
        private EventLogManager _eventLogManager;
        private EventCorrelationEngine _eventCorrelationEngine;

        public AlertIntegrationManager(AlertManager alertManager, MitigationEngine mitigationEngine, ILogger logger)
        {
            _alertManager = alertManager ?? throw new ArgumentNullException(nameof(alertManager));
            _mitigationEngine = mitigationEngine ?? throw new ArgumentNullException(nameof(mitigationEngine));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Initializes connections to all monitoring modules and subscribes to their events
        /// </summary>
        public void Initialize()
        {
            try
            {
                _logger.LogInfo("Initializing Alert Integration Manager...");
                
                // Register for alert events
                _alertManager.AlertGenerated += AlertManager_AlertGenerated;
                _alertManager.AlertAcknowledged += AlertManager_AlertAcknowledged;
                _mitigationEngine.MitigationActionPerformed += MitigationEngine_MitigationActionPerformed;
                
                _logger.LogInfo("Alert Integration Manager initialized successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing Alert Integration Manager: {ex.Message}", ex);
                throw;
            }
        }

        /// <summary>
        /// Connects to the System Monitoring module and subscribes to its events
        /// </summary>
        public void ConnectSystemMonitor(SystemMonitor systemMonitor)
        {
            try
            {
                _systemMonitor = systemMonitor ?? throw new ArgumentNullException(nameof(systemMonitor));
                
                // Subscribe to system monitoring events
                _systemMonitor.CpuThresholdExceeded += SystemMonitor_CpuThresholdExceeded;
                _systemMonitor.MemoryThresholdExceeded += SystemMonitor_MemoryThresholdExceeded;
                _systemMonitor.DiskSpaceCritical += SystemMonitor_DiskSpaceCritical;
                _systemMonitor.SystemError += SystemMonitor_SystemError;
                
                _logger.LogInfo("Connected to System Monitor module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to System Monitor: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the Authentication Monitoring module and subscribes to its events
        /// </summary>
        public void ConnectAuthenticationMonitor(AuthenticationMonitor authenticationMonitor)
        {
            try
            {
                _authenticationMonitor = authenticationMonitor ?? throw new ArgumentNullException(nameof(authenticationMonitor));
                
                // Subscribe to authentication monitoring events
                _authenticationMonitor.FailedLoginAttempt += AuthenticationMonitor_FailedLoginAttempt;
                _authenticationMonitor.BruteForceAttemptDetected += AuthenticationMonitor_BruteForceAttemptDetected;
                _authenticationMonitor.PrivilegeEscalationAttempt += AuthenticationMonitor_PrivilegeEscalationAttempt;
                _authenticationMonitor.UnauthorizedAccessAttempt += AuthenticationMonitor_UnauthorizedAccessAttempt;
                
                _logger.LogInfo("Connected to Authentication Monitor module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to Authentication Monitor: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the File & Registry Monitoring module and subscribes to its events
        /// </summary>
        public void ConnectFileRegistryMonitor(FileRegistryMonitor fileRegistryMonitor)
        {
            try
            {
                _fileRegistryMonitor = fileRegistryMonitor ?? throw new ArgumentNullException(nameof(fileRegistryMonitor));
                
                // Subscribe to file and registry monitoring events
                _fileRegistryMonitor.SensitiveFileAccessed += FileRegistryMonitor_SensitiveFileAccessed;
                _fileRegistryMonitor.SensitiveRegistryKeyModified += FileRegistryMonitor_SensitiveRegistryKeyModified;
                _fileRegistryMonitor.UnauthorizedFileModification += FileRegistryMonitor_UnauthorizedFileModification;
                _fileRegistryMonitor.SuspiciousFileCreated += FileRegistryMonitor_SuspiciousFileCreated;
                
                _logger.LogInfo("Connected to File & Registry Monitor module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to File & Registry Monitor: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the Process Monitoring module and subscribes to its events
        /// </summary>
        public void ConnectProcessMonitor(ProcessMonitor processMonitor)
        {
            try
            {
                _processMonitor = processMonitor ?? throw new ArgumentNullException(nameof(processMonitor));
                
                // Subscribe to process monitoring events
                _processMonitor.SuspiciousProcessStarted += ProcessMonitor_SuspiciousProcessStarted;
                _processMonitor.UnauthorizedProcessAccess += ProcessMonitor_UnauthorizedProcessAccess;
                _processMonitor.MalwareDetected += ProcessMonitor_MalwareDetected;
                _processMonitor.AnomalousProcessBehavior += ProcessMonitor_AnomalousProcessBehavior;
                
                _logger.LogInfo("Connected to Process Monitor module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to Process Monitor: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the Network Monitoring module and subscribes to its events
        /// </summary>
        public void ConnectNetworkMonitor(NetworkMonitor networkMonitor)
        {
            try
            {
                _networkMonitor = networkMonitor ?? throw new ArgumentNullException(nameof(networkMonitor));
                
                // Subscribe to network monitoring events
                _networkMonitor.SuspiciousConnectionDetected += NetworkMonitor_SuspiciousConnectionDetected;
                _networkMonitor.UnauthorizedPortAccess += NetworkMonitor_UnauthorizedPortAccess;
                _networkMonitor.DataExfiltrationAttempt += NetworkMonitor_DataExfiltrationAttempt;
                _networkMonitor.DDoSAttackDetected += NetworkMonitor_DDoSAttackDetected;
                
                _logger.LogInfo("Connected to Network Monitor module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to Network Monitor: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the Vulnerability Scanner module and subscribes to its events
        /// </summary>
        public void ConnectVulnerabilityScanner(VulnerabilityScanner vulnerabilityScanner)
        {
            try
            {
                _vulnerabilityScanner = vulnerabilityScanner ?? throw new ArgumentNullException(nameof(vulnerabilityScanner));
                
                // Subscribe to vulnerability scanner events
                _vulnerabilityScanner.VulnerabilityDetected += VulnerabilityScanner_VulnerabilityDetected;
                _vulnerabilityScanner.ComplianceViolationDetected += VulnerabilityScanner_ComplianceViolationDetected;
                _vulnerabilityScanner.CriticalPatchMissing += VulnerabilityScanner_CriticalPatchMissing;
                
                _logger.LogInfo("Connected to Vulnerability Scanner module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to Vulnerability Scanner: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Connects to the Event Log Management module and subscribes to its events
        /// </summary>
        public void ConnectEventLogManager(EventLogManager eventLogManager, EventCorrelationEngine eventCorrelationEngine)
        {
            try
            {
                _eventLogManager = eventLogManager ?? throw new ArgumentNullException(nameof(eventLogManager));
                _eventCorrelationEngine = eventCorrelationEngine ?? throw new ArgumentNullException(nameof(eventCorrelationEngine));
                
                // Subscribe to event log management events
                _eventLogManager.CriticalEventDetected += EventLogManager_CriticalEventDetected;
                _eventCorrelationEngine.CorrelationRuleTriggered += EventCorrelationEngine_CorrelationRuleTriggered;
                
                _logger.LogInfo("Connected to Event Log Manager module.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error connecting to Event Log Manager: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Disconnects from all monitoring modules and unsubscribes from their events
        /// </summary>
        public void Disconnect()
        {
            try
            {
                _logger.LogInfo("Disconnecting Alert Integration Manager from all modules...");
                
                // Unsubscribe from alert events
                if (_alertManager != null)
                {
                    _alertManager.AlertGenerated -= AlertManager_AlertGenerated;
                    _alertManager.AlertAcknowledged -= AlertManager_AlertAcknowledged;
                }
                
                if (_mitigationEngine != null)
                {
                    _mitigationEngine.MitigationActionPerformed -= MitigationEngine_MitigationActionPerformed;
                }
                
                // Unsubscribe from system monitoring events
                if (_systemMonitor != null)
                {
                    _systemMonitor.CpuThresholdExceeded -= SystemMonitor_CpuThresholdExceeded;
                    _systemMonitor.MemoryThresholdExceeded -= SystemMonitor_MemoryThresholdExceeded;
                    _systemMonitor.DiskSpaceCritical -= SystemMonitor_DiskSpaceCritical;
                    _systemMonitor.SystemError -= SystemMonitor_SystemError;
                }
                
                // Unsubscribe from authentication monitoring events
                if (_authenticationMonitor != null)
                {
                    _authenticationMonitor.FailedLoginAttempt -= AuthenticationMonitor_FailedLoginAttempt;
                    _authenticationMonitor.BruteForceAttemptDetected -= AuthenticationMonitor_BruteForceAttemptDetected;
                    _authenticationMonitor.PrivilegeEscalationAttempt -= AuthenticationMonitor_PrivilegeEscalationAttempt;
                    _authenticationMonitor.UnauthorizedAccessAttempt -= AuthenticationMonitor_UnauthorizedAccessAttempt;
                }
                
                // Unsubscribe from file and registry monitoring events
                if (_fileRegistryMonitor != null)
                {
                    _fileRegistryMonitor.SensitiveFileAccessed -= FileRegistryMonitor_SensitiveFileAccessed;
                    _fileRegistryMonitor.SensitiveRegistryKeyModified -= FileRegistryMonitor_SensitiveRegistryKeyModified;
                    _fileRegistryMonitor.UnauthorizedFileModification -= FileRegistryMonitor_UnauthorizedFileModification;
                    _fileRegistryMonitor.SuspiciousFileCreated -= FileRegistryMonitor_SuspiciousFileCreated;
                }
                
                // Unsubscribe from process monitoring events
                if (_processMonitor != null)
                {
                    _processMonitor.SuspiciousProcessStarted -= ProcessMonitor_SuspiciousProcessStarted;
                    _processMonitor.UnauthorizedProcessAccess -= ProcessMonitor_UnauthorizedProcessAccess;
                    _processMonitor.MalwareDetected -= ProcessMonitor_MalwareDetected;
                    _processMonitor.AnomalousProcessBehavior -= ProcessMonitor_AnomalousProcessBehavior;
                }
                
                // Unsubscribe from network monitoring events
                if (_networkMonitor != null)
                {
                    _networkMonitor.SuspiciousConnectionDetected -= NetworkMonitor_SuspiciousConnectionDetected;
                    _networkMonitor.UnauthorizedPortAccess -= NetworkMonitor_UnauthorizedPortAccess;
                    _networkMonitor.DataExfiltrationAttempt -= NetworkMonitor_DataExfiltrationAttempt;
                    _networkMonitor.DDoSAttackDetected -= NetworkMonitor_DDoSAttackDetected;
                }
                
                // Unsubscribe from vulnerability scanner events
                if (_vulnerabilityScanner != null)
                {
                    _vulnerabilityScanner.VulnerabilityDetected -= VulnerabilityScanner_VulnerabilityDetected;
                    _vulnerabilityScanner.ComplianceViolationDetected -= VulnerabilityScanner_ComplianceViolationDetected;
                    _vulnerabilityScanner.CriticalPatchMissing -= VulnerabilityScanner_CriticalPatchMissing;
                }
                
                // Unsubscribe from event log management events
                if (_eventLogManager != null)
                {
                    _eventLogManager.CriticalEventDetected -= EventLogManager_CriticalEventDetected;
                }
                
                if (_eventCorrelationEngine != null)
                {
                    _eventCorrelationEngine.CorrelationRuleTriggered -= EventCorrelationEngine_CorrelationRuleTriggered;
                }
                
                _logger.LogInfo("Alert Integration Manager disconnected from all modules.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error disconnecting Alert Integration Manager: {ex.Message}", ex);
            }
        }

        #region Alert Manager Event Handlers

        private void AlertManager_AlertGenerated(object sender, AlertEventArgs e)
        {
            _logger.LogInfo($"Alert generated: {e.Alert.Title} (ID: {e.Alert.ID}, Severity: {e.Alert.Severity})");
            
            // Apply automatic mitigation if applicable
            Task.Run(async () =>
            {
                try
                {
                    await _mitigationEngine.ApplyAutomaticMitigationAsync(e.Alert);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error applying automatic mitigation for alert {e.Alert.ID}: {ex.Message}", ex);
                }
            });
        }

        private void AlertManager_AlertAcknowledged(object sender, AlertEventArgs e)
        {
            _logger.LogInfo($"Alert acknowledged: {e.Alert.Title} (ID: {e.Alert.ID})");
        }

        private void MitigationEngine_MitigationActionPerformed(object sender, MitigationActionEventArgs e)
        {
            _logger.LogInfo($"Mitigation action performed: {e.Action.ActionType} for alert {e.Action.AlertID}");
        }

        #endregion

        #region System Monitor Event Handlers

        private void SystemMonitor_CpuThresholdExceeded(object sender, CpuThresholdEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "CpuUsage", e.CpuUsagePercentage },
                { "Threshold", e.ThresholdPercentage },
                { "Duration", e.DurationSeconds }
            };
            
            _alertManager.CreateAlert(
                "High CPU Usage Detected",
                $"CPU usage has exceeded the threshold of {e.ThresholdPercentage}% for {e.DurationSeconds} seconds. Current usage: {e.CpuUsagePercentage}%",
                AlertSeverity.Medium,
                AlertType.System,
                "System Monitor",
                additionalData);
        }

        private void SystemMonitor_MemoryThresholdExceeded(object sender, MemoryThresholdEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "MemoryUsage", e.MemoryUsagePercentage },
                { "Threshold", e.ThresholdPercentage },
                { "AvailableMemory", e.AvailableMemoryMB }
            };
            
            _alertManager.CreateAlert(
                "High Memory Usage Detected",
                $"Memory usage has exceeded the threshold of {e.ThresholdPercentage}%. Available memory: {e.AvailableMemoryMB}MB",
                AlertSeverity.Medium,
                AlertType.System,
                "System Monitor",
                additionalData);
        }

        private void SystemMonitor_DiskSpaceCritical(object sender, DiskSpaceEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "DriveLetter", e.DriveLetter },
                { "FreeSpacePercentage", e.FreeSpacePercentage },
                { "FreeSpaceBytes", e.FreeSpaceBytes },
                { "Threshold", e.ThresholdPercentage }
            };
            
            _alertManager.CreateAlert(
                "Critical Disk Space",
                $"Drive {e.DriveLetter} has only {e.FreeSpacePercentage}% free space remaining ({FormatBytes(e.FreeSpaceBytes)})",
                AlertSeverity.High,
                AlertType.System,
                "System Monitor",
                additionalData);
        }

        private void SystemMonitor_SystemError(object sender, SystemErrorEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ErrorCode", e.ErrorCode },
                { "ErrorSource", e.ErrorSource },
                { "ErrorDetails", e.ErrorDetails }
            };
            
            _alertManager.CreateAlert(
                "System Error Detected",
                $"System error detected from {e.ErrorSource}: {e.ErrorMessage}",
                AlertSeverity.High,
                AlertType.System,
                "System Monitor",
                additionalData);
        }

        #endregion

        #region Authentication Monitor Event Handlers

        private void AuthenticationMonitor_FailedLoginAttempt(object sender, FailedLoginEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "Username", e.Username },
                { "SourceIP", e.SourceIP },
                { "AttemptCount", e.AttemptCount },
                { "TimeStamp", e.Timestamp }
            };
            
            var severity = e.AttemptCount > 5 ? AlertSeverity.Medium : AlertSeverity.Low;
            
            _alertManager.CreateAlert(
                "Failed Login Attempt",
                $"Failed login attempt for user '{e.Username}' from IP {e.SourceIP}. Attempt #{e.AttemptCount}",
                severity,
                AlertType.User,
                "Authentication Monitor",
                additionalData);
        }

        private void AuthenticationMonitor_BruteForceAttemptDetected(object sender, BruteForceEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "Username", e.Username },
                { "SourceIP", e.SourceIP },
                { "AttemptCount", e.AttemptCount },
                { "TimeWindow", e.TimeWindowMinutes }
            };
            
            _alertManager.CreateAlert(
                "Brute Force Attack Detected",
                $"Possible brute force attack detected for user '{e.Username}' from IP {e.SourceIP}. {e.AttemptCount} attempts in {e.TimeWindowMinutes} minutes",
                AlertSeverity.High,
                AlertType.User,
                "Authentication Monitor",
                additionalData);
        }

        private void AuthenticationMonitor_PrivilegeEscalationAttempt(object sender, PrivilegeEscalationEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "Username", e.Username },
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "TargetPrivilege", e.TargetPrivilege }
            };
            
            _alertManager.CreateAlert(
                "Privilege Escalation Attempt",
                $"Privilege escalation attempt detected for user '{e.Username}' via process '{e.ProcessName}' (PID: {e.ProcessID})",
                AlertSeverity.High,
                AlertType.User,
                "Authentication Monitor",
                additionalData);
        }

        private void AuthenticationMonitor_UnauthorizedAccessAttempt(object sender, UnauthorizedAccessEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "Username", e.Username },
                { "ResourceType", e.ResourceType },
                { "ResourcePath", e.ResourcePath },
                { "AccessType", e.AccessType }
            };
            
            _alertManager.CreateAlert(
                "Unauthorized Access Attempt",
                $"Unauthorized {e.AccessType} access attempt by user '{e.Username}' to {e.ResourceType}: {e.ResourcePath}",
                AlertSeverity.Medium,
                AlertType.User,
                "Authentication Monitor",
                additionalData);
        }

        #endregion

        #region File & Registry Monitor Event Handlers

        private void FileRegistryMonitor_SensitiveFileAccessed(object sender, FileAccessEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "FilePath", e.FilePath },
                { "Username", e.Username },
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "AccessType", e.AccessType }
            };
            
            _alertManager.CreateAlert(
                "Sensitive File Accessed",
                $"Sensitive file accessed: {e.FilePath} by user '{e.Username}' via process '{e.ProcessName}' (PID: {e.ProcessID})",
                AlertSeverity.Medium,
                AlertType.File,
                "File & Registry Monitor",
                additionalData);
        }

        private void FileRegistryMonitor_SensitiveRegistryKeyModified(object sender, RegistryAccessEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "RegistryKey", e.RegistryKey },
                { "Username", e.Username },
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "OldValue", e.OldValue },
                { "NewValue", e.NewValue }
            };
            
            _alertManager.CreateAlert(
                "Sensitive Registry Key Modified",
                $"Sensitive registry key modified: {e.RegistryKey} by user '{e.Username}' via process '{e.ProcessName}' (PID: {e.ProcessID})",
                AlertSeverity.High,
                AlertType.Registry,
                "File & Registry Monitor",
                additionalData);
        }

        private void FileRegistryMonitor_UnauthorizedFileModification(object sender, FileModificationEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "FilePath", e.FilePath },
                { "Username", e.Username },
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "ModificationType", e.ModificationType }
            };
            
            _alertManager.CreateAlert(
                "Unauthorized File Modification",
                $"Unauthorized file modification: {e.FilePath} ({e.ModificationType}) by user '{e.Username}' via process '{e.ProcessName}' (PID: {e.ProcessID})",
                AlertSeverity.High,
                AlertType.File,
                "File & Registry Monitor",
                additionalData);
        }

        private void FileRegistryMonitor_SuspiciousFileCreated(object sender, FileCreationEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "FilePath", e.FilePath },
                { "Username", e.Username },
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "FileSize", e.FileSize },
                { "FileHash", e.FileHash }
            };
            
            _alertManager.CreateAlert(
                "Suspicious File Created",
                $"Suspicious file created: {e.FilePath} by user '{e.Username}' via process '{e.ProcessName}' (PID: {e.ProcessID})",
                AlertSeverity.Medium,
                AlertType.File,
                "File & Registry Monitor",
                additionalData);
        }

        #endregion

        #region Process Monitor Event Handlers

        private void ProcessMonitor_SuspiciousProcessStarted(object sender, ProcessStartEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "CommandLine", e.CommandLine },
                { "Username", e.Username },
                { "ParentProcessID", e.ParentProcessID },
                { "ParentProcessName", e.ParentProcessName }
            };
            
            _alertManager.CreateAlert(
                "Suspicious Process Started",
                $"Suspicious process started: '{e.ProcessName}' (PID: {e.ProcessID}) by user '{e.Username}'",
                AlertSeverity.Medium,
                AlertType.Process,
                "Process Monitor",
                additionalData);
        }

        private void ProcessMonitor_UnauthorizedProcessAccess(object sender, ProcessAccessEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "SourceProcessID", e.SourceProcessID },
                { "SourceProcessName", e.SourceProcessName },
                { "TargetProcessID", e.TargetProcessID },
                { "TargetProcessName", e.TargetProcessName },
                { "AccessType", e.AccessType },
                { "Username", e.Username }
            };
            
            _alertManager.CreateAlert(
                "Unauthorized Process Access",
                $"Unauthorized process access: '{e.SourceProcessName}' (PID: {e.SourceProcessID}) accessed '{e.TargetProcessName}' (PID: {e.TargetProcessID})",
                AlertSeverity.High,
                AlertType.Process,
                "Process Monitor",
                additionalData);
        }

        private void ProcessMonitor_MalwareDetected(object sender, MalwareDetectionEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "FilePath", e.FilePath },
                { "MalwareType", e.MalwareType },
                { "ThreatLevel", e.ThreatLevel },
                { "SignatureID", e.SignatureID }
            };
            
            _alertManager.CreateAlert(
                "Malware Detected",
                $"Malware detected: {e.MalwareType} in process '{e.ProcessName}' (PID: {e.ProcessID}), file: {e.FilePath}",
                AlertSeverity.High,
                AlertType.Malware,
                "Process Monitor",
                additionalData);
        }

        private void ProcessMonitor_AnomalousProcessBehavior(object sender, ProcessBehaviorEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "BehaviorType", e.BehaviorType },
                { "Details", e.Details },
                { "Username", e.Username }
            };
            
            _alertManager.CreateAlert(
                "Anomalous Process Behavior",
                $"Anomalous behavior detected in process '{e.ProcessName}' (PID: {e.ProcessID}): {e.BehaviorType}",
                AlertSeverity.Medium,
                AlertType.Process,
                "Process Monitor",
                additionalData);
        }

        #endregion

        #region Network Monitor Event Handlers

        private void NetworkMonitor_SuspiciousConnectionDetected(object sender, ConnectionEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "LocalAddress", e.LocalAddress },
                { "LocalPort", e.LocalPort },
                { "RemoteAddress", e.RemoteAddress },
                { "RemotePort", e.RemotePort },
                { "Protocol", e.Protocol },
                { "Direction", e.Direction }
            };
            
            _alertManager.CreateAlert(
                "Suspicious Network Connection",
                $"Suspicious {e.Direction} connection detected from process '{e.ProcessName}' (PID: {e.ProcessID}) to {e.RemoteAddress}:{e.RemotePort}",
                AlertSeverity.Medium,
                AlertType.Network,
                "Network Monitor",
                additionalData);
        }

        private void NetworkMonitor_UnauthorizedPortAccess(object sender, PortAccessEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "LocalPort", e.Port },
                { "Protocol", e.Protocol },
                { "Username", e.Username }
            };
            
            _alertManager.CreateAlert(
                "Unauthorized Port Access",
                $"Unauthorized port access detected: Process '{e.ProcessName}' (PID: {e.ProcessID}) accessed port {e.Port}/{e.Protocol}",
                AlertSeverity.High,
                AlertType.Network,
                "Network Monitor",
                additionalData);
        }

        private void NetworkMonitor_DataExfiltrationAttempt(object sender, DataExfiltrationEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ProcessID", e.ProcessID },
                { "ProcessName", e.ProcessName },
                { "DestinationAddress", e.DestinationAddress },
                { "DestinationPort", e.DestinationPort },
                { "DataSize", e.DataSizeBytes },
                { "DataType", e.DataType }
            };
            
            _alertManager.CreateAlert(
                "Data Exfiltration Attempt",
                $"Possible data exfiltration detected: Process '{e.ProcessName}' (PID: {e.ProcessID}) sending {FormatBytes(e.DataSizeBytes)} of {e.DataType} data to {e.DestinationAddress}:{e.DestinationPort}",
                AlertSeverity.High,
                AlertType.Network,
                "Network Monitor",
                additionalData);
        }

        private void NetworkMonitor_DDoSAttackDetected(object sender, DDoSEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "TargetAddress", e.TargetAddress },
                { "TargetPort", e.TargetPort },
                { "Protocol", e.Protocol },
                { "PacketCount", e.PacketCount },
                { "TimeWindowSeconds", e.TimeWindowSeconds },
                { "AttackType", e.AttackType }
            };
            
            _alertManager.CreateAlert(
                "DDoS Attack Detected",
                $"Possible DDoS attack detected: {e.AttackType} attack targeting {e.TargetAddress}:{e.TargetPort} ({e.PacketCount} packets in {e.TimeWindowSeconds} seconds)",
                AlertSeverity.High,
                AlertType.Network,
                "Network Monitor",
                additionalData);
        }

        #endregion

        #region Vulnerability Scanner Event Handlers

        private void VulnerabilityScanner_VulnerabilityDetected(object sender, VulnerabilityEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "VulnerabilityID", e.VulnerabilityID },
                { "CVE", e.CVE },
                { "AffectedComponent", e.AffectedComponent },
                { "AffectedVersion", e.AffectedVersion },
                { "RecommendedFix", e.RecommendedFix },
                { "ExploitAvailable", e.ExploitAvailable }
            };
            
            var severity = e.ExploitAvailable ? AlertSeverity.High : AlertSeverity.Medium;
            
            _alertManager.CreateAlert(
                $"Vulnerability Detected: {e.VulnerabilityID}",
                $"Vulnerability detected in {e.AffectedComponent} {e.AffectedVersion}: {e.Description} (CVE: {e.CVE})",
                severity,
                AlertType.Vulnerability,
                "Vulnerability Scanner",
                additionalData);
        }

        private void VulnerabilityScanner_ComplianceViolationDetected(object sender, ComplianceEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "ComplianceID", e.ComplianceID },
                { "Standard", e.Standard },
                { "Requirement", e.Requirement },
                { "AffectedComponent", e.AffectedComponent },
                { "RecommendedFix", e.RecommendedFix }
            };
            
            _alertManager.CreateAlert(
                $"Compliance Violation: {e.Standard}",
                $"Compliance violation detected: {e.Description} (Standard: {e.Standard}, Requirement: {e.Requirement})",
                AlertSeverity.Medium,
                AlertType.Compliance,
                "Vulnerability Scanner",
                additionalData);
        }

        private void VulnerabilityScanner_CriticalPatchMissing(object sender, PatchEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "PatchID", e.PatchID },
                { "CVE", e.CVE },
                { "AffectedComponent", e.AffectedComponent },
                { "CurrentVersion", e.CurrentVersion },
                { "RequiredVersion", e.RequiredVersion },
                { "ReleaseDate", e.ReleaseDate }
            };
            
            _alertManager.CreateAlert(
                "Critical Patch Missing",
                $"Critical security patch missing for {e.AffectedComponent}: {e.Description} (Current version: {e.CurrentVersion}, Required: {e.RequiredVersion})",
                AlertSeverity.High,
                AlertType.Vulnerability,
                "Vulnerability Scanner",
                additionalData);
        }

        #endregion

        #region Event Log Manager Event Handlers

        private void EventLogManager_CriticalEventDetected(object sender, CriticalEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "EventID", e.EventID },
                { "EventSource", e.EventSource },
                { "EventLog", e.EventLog },
                { "EventData", e.EventData }
            };
            
            _alertManager.CreateAlert(
                $"Critical Event Log Entry: {e.EventID}",
                $"Critical event detected in {e.EventLog} log from {e.EventSource}: {e.Message}",
                AlertSeverity.High,
                AlertType.EventLog,
                "Event Log Manager",
                additionalData);
        }

        private void EventCorrelationEngine_CorrelationRuleTriggered(object sender, CorrelationRuleEventArgs e)
        {
            var additionalData = new Dictionary<string, object>
            {
                { "RuleID", e.RuleID },
                { "RuleName", e.RuleName },
                { "MatchedEvents", e.MatchedEvents },
                { "CorrelationScore", e.CorrelationScore }
            };
            
            _alertManager.CreateAlert(
                $"Event Correlation Rule Triggered: {e.RuleName}",
                $"Event correlation rule triggered: {e.Description} (Correlation Score: {e.CorrelationScore})",
                AlertSeverity.High,
                AlertType.EventLog,
                "Event Correlation Engine",
                additionalData);
        }

        #endregion

        #region Helper Methods

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;
            
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            
            return $"{number:n2} {suffixes[counter]}";
        }

        #endregion
    }
}