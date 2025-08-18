using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Threading.Tasks;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Alert
{
    /// <summary>
    /// Types of mitigation actions that can be performed
    /// </summary>
    public enum MitigationActionType
    {
        BlockIP,
        KillProcess,
        QuarantineFile,
        DisableUserAccount,
        Custom
    }

    /// <summary>
    /// Result of a mitigation action
    /// </summary>
    public enum MitigationResult
    {
        Success,
        Failure,
        PartialSuccess,
        NotAttempted,
        NotSupported
    }

    /// <summary>
    /// Configuration for a mitigation rule
    /// </summary>
    public class MitigationRule
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool Enabled { get; set; }
        public AlertType AlertType { get; set; }
        public AlertSeverity MinimumSeverity { get; set; }
        public MitigationActionType ActionType { get; set; }
        public Dictionary<string, string> ActionParameters { get; set; }

        public MitigationRule()
        {
            Id = Guid.NewGuid();
            Enabled = true;
            ActionParameters = new Dictionary<string, string>();
        }
    }

    /// <summary>
    /// Details of a mitigation action that was performed
    /// </summary>
    public class MitigationAction
    {
        public Guid Id { get; set; }
        public Guid AlertId { get; set; }
        public Guid? RuleId { get; set; }
        public MitigationActionType ActionType { get; set; }
        public Dictionary<string, string> Parameters { get; set; }
        public MitigationResult Result { get; set; }
        public string ResultDetails { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsAutomatic { get; set; }

        public MitigationAction()
        {
            Id = Guid.NewGuid();
            Parameters = new Dictionary<string, string>();
            Timestamp = DateTime.Now;
        }
    }

    /// <summary>
    /// Event arguments for when a mitigation action is performed
    /// </summary>
    public class MitigationActionEventArgs : EventArgs
    {
        public MitigationAction Action { get; set; }
        public Alert Alert { get; set; }

        public MitigationActionEventArgs(MitigationAction action, Alert alert)
        {
            Action = action;
            Alert = alert;
        }
    }

    /// <summary>
    /// Event arguments for when an error occurs in the MitigationEngine
    /// </summary>
    public class MitigationEngineErrorEventArgs : EventArgs
    {
        public string ErrorMessage { get; set; }
        public Exception Exception { get; set; }

        public MitigationEngineErrorEventArgs(string errorMessage, Exception exception = null)
        {
            ErrorMessage = errorMessage;
            Exception = exception;
        }
    }

    /// <summary>
    /// Engine for performing automatic and manual mitigation actions in response to alerts
    /// </summary>
    public class MitigationEngine
    {
        private readonly object _ruleLock = new object();
        private readonly object _actionLock = new object();
        private readonly AlertManager _alertManager;
        private readonly List<MitigationRule> _rules;
        private readonly List<MitigationAction> _actions;
        private readonly string _quarantineFolder;

        // Properties
        public bool AutoMitigationEnabled { get; set; }
        public IReadOnlyList<MitigationRule> Rules => _rules.AsReadOnly();
        public IReadOnlyList<MitigationAction> Actions => _actions.AsReadOnly();

        // Events
        public event EventHandler<MitigationActionEventArgs> MitigationActionPerformed;
        public event EventHandler<MitigationEngineErrorEventArgs> MitigationEngineError;

        /// <summary>
        /// Initializes a new instance of the MitigationEngine class
        /// </summary>
        /// <param name="alertManager">The alert manager to use</param>
        /// <param name="quarantineFolder">Folder to use for quarantined files</param>
        public MitigationEngine(AlertManager alertManager, string quarantineFolder = null)
        {
            _alertManager = alertManager ?? throw new ArgumentNullException(nameof(alertManager));
            _rules = new List<MitigationRule>();
            _actions = new List<MitigationAction>();
            
            // Set up quarantine folder
            _quarantineFolder = quarantineFolder ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "WinSecMonitor", "Quarantine");
            
            // Ensure quarantine folder exists
            try
            {
                if (!Directory.Exists(_quarantineFolder))
                {
                    Directory.CreateDirectory(_quarantineFolder);
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error creating quarantine folder: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
            
            // Subscribe to alert events
            _alertManager.AlertGenerated += AlertManager_AlertGenerated;
            
            // Initialize with default rules
            InitializeDefaultRules();
            
            // Enable auto-mitigation by default
            AutoMitigationEnabled = true;
        }

        /// <summary>
        /// Adds a new mitigation rule
        /// </summary>
        /// <param name="rule">The rule to add</param>
        public void AddRule(MitigationRule rule)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));
            
            lock (_ruleLock)
            {
                _rules.Add(rule);
                Logger.Log($"Added mitigation rule: {rule.Name}");
            }
        }

        /// <summary>
        /// Updates an existing mitigation rule
        /// </summary>
        /// <param name="rule">The updated rule</param>
        /// <returns>True if successful, false if rule not found</returns>
        public bool UpdateRule(MitigationRule rule)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));
            
            lock (_ruleLock)
            {
                int index = _rules.FindIndex(r => r.Id == rule.Id);
                if (index >= 0)
                {
                    _rules[index] = rule;
                    Logger.Log($"Updated mitigation rule: {rule.Name}");
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Removes a mitigation rule
        /// </summary>
        /// <param name="ruleId">ID of the rule to remove</param>
        /// <returns>True if successful, false if rule not found</returns>
        public bool RemoveRule(Guid ruleId)
        {
            lock (_ruleLock)
            {
                int index = _rules.FindIndex(r => r.Id == ruleId);
                if (index >= 0)
                {
                    string ruleName = _rules[index].Name;
                    _rules.RemoveAt(index);
                    Logger.Log($"Removed mitigation rule: {ruleName}");
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Enables or disables a mitigation rule
        /// </summary>
        /// <param name="ruleId">ID of the rule</param>
        /// <param name="enabled">Whether to enable or disable the rule</param>
        /// <returns>True if successful, false if rule not found</returns>
        public bool SetRuleEnabled(Guid ruleId, bool enabled)
        {
            lock (_ruleLock)
            {
                var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
                if (rule != null)
                {
                    rule.Enabled = enabled;
                    Logger.Log($"{(enabled ? "Enabled" : "Disabled")} mitigation rule: {rule.Name}");
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Gets mitigation rules filtered by various criteria
        /// </summary>
        /// <param name="enabled">Filter by enabled status</param>
        /// <param name="actionType">Filter by action type</param>
        /// <param name="alertType">Filter by alert type</param>
        /// <param name="minimumSeverity">Filter by minimum severity</param>
        /// <returns>Collection of filtered rules</returns>
        public IEnumerable<MitigationRule> GetFilteredRules(
            bool? enabled = null,
            MitigationActionType? actionType = null,
            AlertType? alertType = null,
            AlertSeverity? minimumSeverity = null)
        {
            lock (_ruleLock)
            {
                IEnumerable<MitigationRule> filteredRules = _rules.AsEnumerable();
                
                if (enabled.HasValue)
                {
                    filteredRules = filteredRules.Where(r => r.Enabled == enabled.Value);
                }
                
                if (actionType.HasValue)
                {
                    filteredRules = filteredRules.Where(r => r.ActionType == actionType.Value);
                }
                
                if (alertType.HasValue)
                {
                    filteredRules = filteredRules.Where(r => r.AlertType == alertType.Value);
                }
                
                if (minimumSeverity.HasValue)
                {
                    filteredRules = filteredRules.Where(r => r.MinimumSeverity <= minimumSeverity.Value);
                }
                
                return filteredRules.ToList(); // Create a copy to avoid thread issues
            }
        }

        /// <summary>
        /// Gets mitigation actions filtered by various criteria
        /// </summary>
        /// <param name="alertId">Filter by alert ID</param>
        /// <param name="ruleId">Filter by rule ID</param>
        /// <param name="actionType">Filter by action type</param>
        /// <param name="result">Filter by result</param>
        /// <param name="isAutomatic">Filter by whether the action was automatic</param>
        /// <param name="startTime">Filter by start time</param>
        /// <param name="endTime">Filter by end time</param>
        /// <returns>Collection of filtered actions</returns>
        public IEnumerable<MitigationAction> GetFilteredActions(
            Guid? alertId = null,
            Guid? ruleId = null,
            MitigationActionType? actionType = null,
            MitigationResult? result = null,
            bool? isAutomatic = null,
            DateTime? startTime = null,
            DateTime? endTime = null)
        {
            lock (_actionLock)
            {
                IEnumerable<MitigationAction> filteredActions = _actions.AsEnumerable();
                
                if (alertId.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.AlertId == alertId.Value);
                }
                
                if (ruleId.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.RuleId == ruleId.Value);
                }
                
                if (actionType.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.ActionType == actionType.Value);
                }
                
                if (result.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.Result == result.Value);
                }
                
                if (isAutomatic.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.IsAutomatic == isAutomatic.Value);
                }
                
                if (startTime.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.Timestamp >= startTime.Value);
                }
                
                if (endTime.HasValue)
                {
                    filteredActions = filteredActions.Where(a => a.Timestamp <= endTime.Value);
                }
                
                return filteredActions.ToList(); // Create a copy to avoid thread issues
            }
        }

        /// <summary>
        /// Performs automatic mitigation for an alert based on configured rules
        /// </summary>
        /// <param name="alert">The alert to mitigate</param>
        /// <returns>The mitigation action performed, or null if no action was taken</returns>
        public MitigationAction AutoMitigate(Alert alert)
        {
            if (alert == null) throw new ArgumentNullException(nameof(alert));
            if (!AutoMitigationEnabled) return null;
            
            try
            {
                // Find applicable rules
                var applicableRules = GetApplicableRules(alert);
                if (!applicableRules.Any()) return null;
                
                // Use the first applicable rule
                var rule = applicableRules.First();
                
                // Create mitigation action
                var action = new MitigationAction
                {
                    AlertId = alert.Id,
                    RuleId = rule.Id,
                    ActionType = rule.ActionType,
                    Parameters = new Dictionary<string, string>(rule.ActionParameters),
                    IsAutomatic = true
                };
                
                // Perform the action
                PerformMitigationAction(action, alert);
                
                // Update the alert with mitigation information
                _alertManager.UpdateAlertMitigation(
                    alert.Id,
                    $"{action.ActionType} via rule '{rule.Name}'.",
                    $"{action.Result}: {action.ResultDetails}",
                    true);
                
                return action;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error performing auto-mitigation for alert {alert.Id}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return null;
            }
        }

        /// <summary>
        /// Manually performs a mitigation action for an alert
        /// </summary>
        /// <param name="alertId">ID of the alert to mitigate</param>
        /// <param name="actionType">Type of action to perform</param>
        /// <param name="parameters">Parameters for the action</param>
        /// <returns>The mitigation action performed, or null if the alert was not found</returns>
        public MitigationAction ManualMitigate(Guid alertId, MitigationActionType actionType, Dictionary<string, string> parameters = null)
        {
            try
            {
                // Find the alert
                var alert = _alertManager.Alerts.FirstOrDefault(a => a.Id == alertId);
                if (alert == null) return null;
                
                // Create mitigation action
                var action = new MitigationAction
                {
                    AlertId = alertId,
                    ActionType = actionType,
                    Parameters = parameters ?? new Dictionary<string, string>(),
                    IsAutomatic = false
                };
                
                // Perform the action
                PerformMitigationAction(action, alert);
                
                // Update the alert with mitigation information
                _alertManager.UpdateAlertMitigation(
                    alertId,
                    $"Manual {action.ActionType}",
                    $"{action.Result}: {action.ResultDetails}",
                    false);
                
                return action;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error performing manual mitigation for alert {alertId}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return null;
            }
        }

        /// <summary>
        /// Blocks an IP address using Windows Firewall
        /// </summary>
        /// <param name="ipAddress">The IP address to block</param>
        /// <param name="ruleName">Name for the firewall rule</param>
        /// <param name="direction">Direction (in/out/both)</param>
        /// <returns>Result of the operation</returns>
        public async Task<(MitigationResult Result, string Details)> BlockIPAsync(string ipAddress, string ruleName = null, string direction = "both")
        {
            try
            {
                // Validate IP address
                if (!IPAddress.TryParse(ipAddress, out _))
                {
                    return (MitigationResult.Failure, $"Invalid IP address format: {ipAddress}");
                }
                
                // Generate rule name if not provided
                if (string.IsNullOrEmpty(ruleName))
                {
                    ruleName = $"WinSecMonitor_Block_{ipAddress}_{DateTime.Now:yyyyMMddHHmmss}";
                }
                
                // Normalize direction
                direction = direction.ToLower();
                if (direction != "in" && direction != "out" && direction != "both")
                {
                    direction = "both";
                }
                
                // Create firewall rules
                var tasks = new List<Task<(bool Success, string Output)>>();
                
                if (direction == "in" || direction == "both")
                {
                    string inCommand = $"netsh advfirewall firewall add rule name=\"{ruleName}_IN\" dir=in action=block remoteip={ipAddress}";
                    tasks.Add(ExecuteCommandAsync(inCommand));
                }
                
                if (direction == "out" || direction == "both")
                {
                    string outCommand = $"netsh advfirewall firewall add rule name=\"{ruleName}_OUT\" dir=out action=block remoteip={ipAddress}";
                    tasks.Add(ExecuteCommandAsync(outCommand));
                }
                
                // Wait for all commands to complete
                var results = await Task.WhenAll(tasks);
                
                // Check results
                bool allSucceeded = results.All(r => r.Success);
                string details = string.Join(Environment.NewLine, results.Select(r => r.Output));
                
                if (allSucceeded)
                {
                    Logger.Log($"Successfully blocked IP {ipAddress} with rule '{ruleName}'");
                    return (MitigationResult.Success, $"Successfully blocked IP {ipAddress}");
                }
                else if (results.Any(r => r.Success))
                {
                    Logger.LogWarning($"Partially blocked IP {ipAddress} with rule '{ruleName}': {details}");
                    return (MitigationResult.PartialSuccess, $"Partially blocked IP {ipAddress}: {details}");
                }
                else
                {
                    Logger.LogError($"Failed to block IP {ipAddress}: {details}");
                    return (MitigationResult.Failure, $"Failed to block IP {ipAddress}: {details}");
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error blocking IP {ipAddress}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
        }

        /// <summary>
        /// Kills a process by ID or name
        /// </summary>
        /// <param name="processIdentifier">Process ID or name</param>
        /// <returns>Result of the operation</returns>
        public (MitigationResult Result, string Details) KillProcess(string processIdentifier)
        {
            try
            {
                // Try to parse as process ID first
                if (int.TryParse(processIdentifier, out int pid))
                {
                    try
                    {
                        Process process = Process.GetProcessById(pid);
                        process.Kill();
                        Logger.Log($"Successfully killed process with ID {pid}");
                        return (MitigationResult.Success, $"Successfully killed process with ID {pid}");
                    }
                    catch (ArgumentException)
                    {
                        return (MitigationResult.Failure, $"Process with ID {pid} not found");
                    }
                    catch (Exception ex)
                    {
                        return (MitigationResult.Failure, $"Failed to kill process with ID {pid}: {ex.Message}");
                    }
                }
                
                // Try as process name
                Process[] processes = Process.GetProcessesByName(processIdentifier);
                if (processes.Length == 0)
                {
                    return (MitigationResult.Failure, $"No processes found with name '{processIdentifier}'");
                }
                
                int successCount = 0;
                List<string> errors = new List<string>();
                
                foreach (var process in processes)
                {
                    try
                    {
                        process.Kill();
                        successCount++;
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Failed to kill process {process.Id}: {ex.Message}");
                    }
                }
                
                if (successCount == processes.Length)
                {
                    Logger.Log($"Successfully killed {successCount} processes with name '{processIdentifier}'");
                    return (MitigationResult.Success, $"Successfully killed {successCount} processes with name '{processIdentifier}'");
                }
                else if (successCount > 0)
                {
                    string details = $"Killed {successCount} out of {processes.Length} processes. Errors: {string.Join("; ", errors)}";
                    Logger.LogWarning($"Partially killed processes with name '{processIdentifier}': {details}");
                    return (MitigationResult.PartialSuccess, details);
                }
                else
                {
                    string details = $"Failed to kill any processes with name '{processIdentifier}'. Errors: {string.Join("; ", errors)}";
                    Logger.LogError(details);
                    return (MitigationResult.Failure, details);
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error killing process {processIdentifier}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
        }

        /// <summary>
        /// Quarantines a file by moving it to the quarantine folder
        /// </summary>
        /// <param name="filePath">Path to the file to quarantine</param>
        /// <returns>Result of the operation</returns>
        public (MitigationResult Result, string Details) QuarantineFile(string filePath)
        {
            try
            {
                // Check if file exists
                if (!File.Exists(filePath))
                {
                    return (MitigationResult.Failure, $"File not found: {filePath}");
                }
                
                // Generate quarantine file name
                string fileName = Path.GetFileName(filePath);
                string quarantineFileName = $"{fileName}_{DateTime.Now:yyyyMMddHHmmss}_{Guid.NewGuid().ToString().Substring(0, 8)}";
                string quarantinePath = Path.Combine(_quarantineFolder, quarantineFileName);
                
                // Create metadata file with original path and timestamp
                string metadataPath = $"{quarantinePath}.meta";
                File.WriteAllText(metadataPath, $"Original Path: {filePath}\nQuarantined: {DateTime.Now}\n");
                
                // Move file to quarantine
                File.Move(filePath, quarantinePath);
                
                Logger.Log($"Successfully quarantined file: {filePath} to {quarantinePath}");
                return (MitigationResult.Success, $"Successfully quarantined file to {quarantinePath}");
            }
            catch (UnauthorizedAccessException ex)
            {
                string errorMessage = $"Access denied when quarantining file {filePath}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
            catch (IOException ex)
            {
                string errorMessage = $"IO error when quarantining file {filePath}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error quarantining file {filePath}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
        }

        /// <summary>
        /// Disables a user account
        /// </summary>
        /// <param name="username">Username to disable</param>
        /// <returns>Result of the operation</returns>
        public async Task<(MitigationResult Result, string Details)> DisableUserAccountAsync(string username)
        {
            try
            {
                // Validate username
                if (string.IsNullOrWhiteSpace(username))
                {
                    return (MitigationResult.Failure, "Username cannot be empty");
                }
                
                // Check if running as administrator
                bool isAdmin = IsRunningAsAdministrator();
                if (!isAdmin)
                {
                    return (MitigationResult.Failure, "Administrator privileges required to disable user accounts");
                }
                
                // Execute command to disable user account
                string command = $"net user {username} /active:no";
                var result = await ExecuteCommandAsync(command);
                
                if (result.Success)
                {
                    Logger.Log($"Successfully disabled user account: {username}");
                    return (MitigationResult.Success, $"Successfully disabled user account: {username}");
                }
                else
                {
                    Logger.LogError($"Failed to disable user account {username}: {result.Output}");
                    return (MitigationResult.Failure, $"Failed to disable user account: {result.Output}");
                }
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error disabling user account {username}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
        }

        /// <summary>
        /// Restores a quarantined file to its original location or a specified path
        /// </summary>
        /// <param name="quarantineFileName">Name of the quarantined file</param>
        /// <param name="restorePath">Path to restore to, or null to use original path</param>
        /// <returns>Result of the operation</returns>
        public (MitigationResult Result, string Details) RestoreQuarantinedFile(string quarantineFileName, string restorePath = null)
        {
            try
            {
                // Build full quarantine path
                string quarantinePath = Path.Combine(_quarantineFolder, quarantineFileName);
                
                // Check if quarantined file exists
                if (!File.Exists(quarantinePath))
                {
                    return (MitigationResult.Failure, $"Quarantined file not found: {quarantinePath}");
                }
                
                // Check for metadata file
                string metadataPath = $"{quarantinePath}.meta";
                string originalPath = null;
                
                if (File.Exists(metadataPath))
                {
                    string[] metadataLines = File.ReadAllLines(metadataPath);
                    foreach (var line in metadataLines)
                    {
                        if (line.StartsWith("Original Path: "))
                        {
                            originalPath = line.Substring("Original Path: ".Length);
                            break;
                        }
                    }
                }
                
                // Determine restore path
                string targetPath = restorePath;
                if (string.IsNullOrEmpty(targetPath))
                {
                    targetPath = originalPath;
                    if (string.IsNullOrEmpty(targetPath))
                    {
                        // If no original path in metadata and no restore path specified, use desktop
                        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                        targetPath = Path.Combine(desktop, Path.GetFileName(quarantineFileName));
                    }
                }
                
                // Check if target path already exists
                if (File.Exists(targetPath))
                {
                    return (MitigationResult.Failure, $"Target path already exists: {targetPath}");
                }
                
                // Move file from quarantine to target path
                File.Move(quarantinePath, targetPath);
                
                // Delete metadata file if it exists
                if (File.Exists(metadataPath))
                {
                    File.Delete(metadataPath);
                }
                
                Logger.Log($"Successfully restored quarantined file to: {targetPath}");
                return (MitigationResult.Success, $"Successfully restored file to {targetPath}");
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error restoring quarantined file {quarantineFileName}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return (MitigationResult.Failure, errorMessage);
            }
        }

        /// <summary>
        /// Gets a list of all quarantined files
        /// </summary>
        /// <returns>List of quarantined files with metadata</returns>
        public List<(string FileName, string OriginalPath, DateTime QuarantineTime)> GetQuarantinedFiles()
        {
            try
            {
                var result = new List<(string FileName, string OriginalPath, DateTime QuarantineTime)>();
                
                if (!Directory.Exists(_quarantineFolder))
                {
                    return result;
                }
                
                // Get all files in quarantine folder that don't have .meta extension
                var files = Directory.GetFiles(_quarantineFolder)
                    .Where(f => !f.EndsWith(".meta"))
                    .ToList();
                
                foreach (var file in files)
                {
                    string fileName = Path.GetFileName(file);
                    string originalPath = "Unknown";
                    DateTime quarantineTime = File.GetCreationTime(file);
                    
                    // Try to read metadata
                    string metadataPath = $"{file}.meta";
                    if (File.Exists(metadataPath))
                    {
                        string[] metadataLines = File.ReadAllLines(metadataPath);
                        foreach (var line in metadataLines)
                        {
                            if (line.StartsWith("Original Path: "))
                            {
                                originalPath = line.Substring("Original Path: ".Length);
                            }
                            else if (line.StartsWith("Quarantined: "))
                            {
                                if (DateTime.TryParse(line.Substring("Quarantined: ".Length), out DateTime parsedTime))
                                {
                                    quarantineTime = parsedTime;
                                }
                            }
                        }
                    }
                    
                    result.Add((fileName, originalPath, quarantineTime));
                }
                
                return result;
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error getting quarantined files: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
                return new List<(string, string, DateTime)>();
            }
        }

        /// <summary>
        /// Disposes resources used by the MitigationEngine
        /// </summary>
        public void Dispose()
        {
            _alertManager.AlertGenerated -= AlertManager_AlertGenerated;
        }

        #region Private Methods

        private void InitializeDefaultRules()
        {
            try
            {
                // Rule for blocking malicious IPs
                AddRule(new MitigationRule
                {
                    Name = "Block Malicious IP",
                    Description = "Automatically blocks IPs detected as malicious",
                    AlertType = AlertType.MaliciousIP,
                    MinimumSeverity = AlertSeverity.Medium,
                    ActionType = MitigationActionType.BlockIP,
                    ActionParameters = new Dictionary<string, string>
                    {
                        { "direction", "both" }
                    }
                });
                
                // Rule for killing suspicious processes
                AddRule(new MitigationRule
                {
                    Name = "Kill Suspicious Process",
                    Description = "Automatically kills processes detected as suspicious",
                    AlertType = AlertType.ProcessSuspicious,
                    MinimumSeverity = AlertSeverity.High,
                    ActionType = MitigationActionType.KillProcess
                });
                
                // Rule for quarantining malicious files
                AddRule(new MitigationRule
                {
                    Name = "Quarantine Malicious File",
                    Description = "Automatically quarantines files detected as malicious",
                    AlertType = AlertType.MaliciousFile,
                    MinimumSeverity = AlertSeverity.Medium,
                    ActionType = MitigationActionType.QuarantineFile
                });
                
                // Rule for disabling compromised user accounts
                AddRule(new MitigationRule
                {
                    Name = "Disable Compromised User Account",
                    Description = "Automatically disables user accounts that appear to be compromised",
                    AlertType = AlertType.UserAuthentication,
                    MinimumSeverity = AlertSeverity.High,
                    ActionType = MitigationActionType.DisableUserAccount,
                    Enabled = false // Disabled by default as it's a high-impact action
                });
            }
            catch (Exception ex)
            {
                string errorMessage = $"Error initializing default rules: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
        }

        private List<MitigationRule> GetApplicableRules(Alert alert)
        {
            lock (_ruleLock)
            {
                return _rules
                    .Where(r => r.Enabled)
                    .Where(r => r.AlertType == alert.Type || r.AlertType == AlertType.Custom)
                    .Where(r => r.MinimumSeverity <= alert.Severity)
                    .OrderBy(r => r.MinimumSeverity) // Prioritize rules with higher severity requirements
                    .ToList();
            }
        }

        private void PerformMitigationAction(MitigationAction action, Alert alert)
        {
            try
            {
                // Extract necessary parameters based on action type
                switch (action.ActionType)
                {
                    case MitigationActionType.BlockIP:
                        PerformBlockIP(action, alert);
                        break;
                        
                    case MitigationActionType.KillProcess:
                        PerformKillProcess(action, alert);
                        break;
                        
                    case MitigationActionType.QuarantineFile:
                        PerformQuarantineFile(action, alert);
                        break;
                        
                    case MitigationActionType.DisableUserAccount:
                        PerformDisableUserAccount(action, alert);
                        break;
                        
                    case MitigationActionType.Custom:
                        action.Result = MitigationResult.NotSupported;
                        action.ResultDetails = "Custom mitigation actions are not supported automatically";
                        break;
                        
                    default:
                        action.Result = MitigationResult.NotSupported;
                        action.ResultDetails = $"Unsupported action type: {action.ActionType}";
                        break;
                }
                
                // Add action to history
                lock (_actionLock)
                {
                    _actions.Add(action);
                }
                
                // Notify subscribers
                OnMitigationActionPerformed(new MitigationActionEventArgs(action, alert));
                
                // Log the action
                LogMitigationAction(action, alert);
            }
            catch (Exception ex)
            {
                action.Result = MitigationResult.Failure;
                action.ResultDetails = $"Error performing mitigation: {ex.Message}";
                
                string errorMessage = $"Error performing mitigation action {action.ActionType} for alert {alert.Id}: {ex.Message}";
                OnMitigationEngineError(new MitigationEngineErrorEventArgs(errorMessage, ex));
                ErrorHandler.LogError(errorMessage, ex);
            }
        }

        private async void PerformBlockIP(MitigationAction action, Alert alert)
        {
            try
            {
                // Extract IP address from alert or parameters
                string ipAddress = null;
                
                // Try to get IP from parameters
                if (action.Parameters.ContainsKey("ip"))
                {
                    ipAddress = action.Parameters["ip"];
                }
                // Try to get IP from alert additional data
                else if (alert.AdditionalData.ContainsKey("ip"))
                {
                    ipAddress = alert.AdditionalData["ip"];
                }
                // Try to extract IP from alert description or title as last resort
                else
                {
                    ipAddress = ExtractIPFromText(alert.Description) ?? ExtractIPFromText(alert.Title);
                }
                
                if (string.IsNullOrEmpty(ipAddress))
                {
                    action.Result = MitigationResult.Failure;
                    action.ResultDetails = "Could not determine IP address to block";
                    return;
                }
                
                // Get direction if specified
                string direction = "both";
                if (action.Parameters.ContainsKey("direction"))
                {
                    direction = action.Parameters["direction"];
                }
                
                // Get rule name if specified
                string ruleName = null;
                if (action.Parameters.ContainsKey("ruleName"))
                {
                    ruleName = action.Parameters["ruleName"];
                }
                
                // Perform the block
                var result = await BlockIPAsync(ipAddress, ruleName, direction);
                action.Result = result.Result;
                action.ResultDetails = result.Details;
            }
            catch (Exception ex)
            {
                action.Result = MitigationResult.Failure;
                action.ResultDetails = $"Error blocking IP: {ex.Message}";
                throw;
            }
        }

        private void PerformKillProcess(MitigationAction action, Alert alert)
        {
            try
            {
                // Extract process identifier from alert or parameters
                string processIdentifier = null;
                
                // Try to get process from parameters
                if (action.Parameters.ContainsKey("process"))
                {
                    processIdentifier = action.Parameters["process"];
                }
                // Try to get process from alert additional data
                else if (alert.AdditionalData.ContainsKey("process"))
                {
                    processIdentifier = alert.AdditionalData["process"];
                }
                else if (alert.AdditionalData.ContainsKey("processId"))
                {
                    processIdentifier = alert.AdditionalData["processId"];
                }
                else if (alert.AdditionalData.ContainsKey("processName"))
                {
                    processIdentifier = alert.AdditionalData["processName"];
                }
                
                if (string.IsNullOrEmpty(processIdentifier))
                {
                    action.Result = MitigationResult.Failure;
                    action.ResultDetails = "Could not determine process to kill";
                    return;
                }
                
                // Perform the kill
                var result = KillProcess(processIdentifier);
                action.Result = result.Result;
                action.ResultDetails = result.Details;
            }
            catch (Exception ex)
            {
                action.Result = MitigationResult.Failure;
                action.ResultDetails = $"Error killing process: {ex.Message}";
                throw;
            }
        }

        private void PerformQuarantineFile(MitigationAction action, Alert alert)
        {
            try
            {
                // Extract file path from alert or parameters
                string filePath = null;
                
                // Try to get file path from parameters
                if (action.Parameters.ContainsKey("filePath"))
                {
                    filePath = action.Parameters["filePath"];
                }
                // Try to get file path from alert additional data
                else if (alert.AdditionalData.ContainsKey("filePath"))
                {
                    filePath = alert.AdditionalData["filePath"];
                }
                else if (alert.AdditionalData.ContainsKey("file"))
                {
                    filePath = alert.AdditionalData["file"];
                }
                
                if (string.IsNullOrEmpty(filePath))
                {
                    action.Result = MitigationResult.Failure;
                    action.ResultDetails = "Could not determine file to quarantine";
                    return;
                }
                
                // Perform the quarantine
                var result = QuarantineFile(filePath);
                action.Result = result.Result;
                action.ResultDetails = result.Details;
            }
            catch (Exception ex)
            {
                action.Result = MitigationResult.Failure;
                action.ResultDetails = $"Error quarantining file: {ex.Message}";
                throw;
            }
        }

        private async void PerformDisableUserAccount(MitigationAction action, Alert alert)
        {
            try
            {
                // Extract username from alert or parameters
                string username = null;
                
                // Try to get username from parameters
                if (action.Parameters.ContainsKey("username"))
                {
                    username = action.Parameters["username"];
                }
                // Try to get username from alert additional data
                else if (alert.AdditionalData.ContainsKey("username"))
                {
                    username = alert.AdditionalData["username"];
                }
                else if (alert.AdditionalData.ContainsKey("user"))
                {
                    username = alert.AdditionalData["user"];
                }
                
                if (string.IsNullOrEmpty(username))
                {
                    action.Result = MitigationResult.Failure;
                    action.ResultDetails = "Could not determine user account to disable";
                    return;
                }
                
                // Perform the disable
                var result = await DisableUserAccountAsync(username);
                action.Result = result.Result;
                action.ResultDetails = result.Details;
            }
            catch (Exception ex)
            {
                action.Result = MitigationResult.Failure;
                action.ResultDetails = $"Error disabling user account: {ex.Message}";
                throw;
            }
        }

        private void AlertManager_AlertGenerated(object sender, AlertGeneratedEventArgs e)
        {
            if (AutoMitigationEnabled)
            {
                // Perform auto-mitigation in a separate task to avoid blocking
                Task.Run(() => AutoMitigate(e.Alert));
            }
        }

        private void LogMitigationAction(MitigationAction action, Alert alert)
        {
            string logMessage = $"Mitigation: {action.ActionType} for alert [{alert.Severity}] {alert.Title} - Result: {action.Result}";
            
            if (action.Result == MitigationResult.Success)
            {
                Logger.Log(logMessage);
            }
            else if (action.Result == MitigationResult.PartialSuccess)
            {
                Logger.LogWarning($"{logMessage} - {action.ResultDetails}");
            }
            else
            {
                Logger.LogError($"{logMessage} - {action.ResultDetails}");
            }
        }

        private async Task<(bool Success, string Output)> ExecuteCommandAsync(string command)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using (var process = new Process { StartInfo = startInfo })
                {
                    process.Start();
                    
                    string output = await process.StandardOutput.ReadToEndAsync();
                    string error = await process.StandardError.ReadToEndAsync();
                    
                    await Task.Run(() => process.WaitForExit());
                    
                    bool success = process.ExitCode == 0;
                    string result = success ? output : $"{output}\n{error}";
                    
                    return (success, result.Trim());
                }
            }
            catch (Exception ex)
            {
                return (false, $"Error executing command: {ex.Message}");
            }
        }

        private bool IsRunningAsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private string ExtractIPFromText(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            
            // Simple regex pattern for IPv4 addresses
            var match = System.Text.RegularExpressions.Regex.Match(
                text,
                @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
            
            return match.Success ? match.Value : null;
        }

        #endregion

        #region Event Handlers

        protected virtual void OnMitigationActionPerformed(MitigationActionEventArgs e)
        {
            MitigationActionPerformed?.Invoke(this, e);
        }

        protected virtual void OnMitigationEngineError(MitigationEngineErrorEventArgs e)
        {
            MitigationEngineError?.Invoke(this, e);
        }

        #endregion
    }
}