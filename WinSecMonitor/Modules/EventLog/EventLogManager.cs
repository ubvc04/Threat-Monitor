using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Timers;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.EventLog
{
    /// <summary>
    /// Manages event log collection, correlation, and threat intelligence integration
    /// </summary>
    public class EventLogManager
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly EventLogCollector _eventLogCollector;
        private readonly EventCorrelationEngine _correlationEngine;
        private readonly ThreatIntelligenceManager _threatIntelligenceManager;
        private readonly RootkitDetector _rootkitDetector;
        private readonly Timer _statusCheckTimer;

        /// <summary>
        /// Event raised when a correlation alert is detected
        /// </summary>
        public event EventHandler<CorrelationAlertEventArgs> CorrelationAlertDetected;

        /// <summary>
        /// Event raised when a rootkit is detected
        /// </summary>
        public event EventHandler<RootkitDetectionEventArgs> RootkitDetected;

        /// <summary>
        /// Event raised when a status check is completed
        /// </summary>
        public event EventHandler<EventLogManagerStatusEventArgs> StatusCheckCompleted;

        /// <summary>
        /// Event raised when an error occurs
        /// </summary>
        public event EventHandler<EventLogManagerErrorEventArgs> ErrorOccurred;

        /// <summary>
        /// Gets or sets the status check interval in milliseconds
        /// </summary>
        public int StatusCheckIntervalMs { get; set; }

        /// <summary>
        /// Gets a value indicating whether the event log collection is active
        /// </summary>
        public bool IsCollectionActive => _eventLogCollector?.IsCollecting ?? false;

        /// <summary>
        /// Gets a value indicating whether the correlation engine is active
        /// </summary>
        public bool IsCorrelationActive => _correlationEngine?.IsRunning ?? false;

        /// <summary>
        /// Gets a value indicating whether the threat intelligence manager is active
        /// </summary>
        public bool IsThreatIntelligenceActive => _threatIntelligenceManager?.IsUpdating ?? false;

        /// <summary>
        /// Gets a value indicating whether the rootkit detector is active
        /// </summary>
        public bool IsRootkitDetectionActive => _rootkitDetector != null;

        /// <summary>
        /// Gets the last status check time
        /// </summary>
        public DateTime LastStatusCheckTime { get; private set; }

        /// <summary>
        /// Gets the total number of correlation alerts
        /// </summary>
        public int TotalCorrelationAlerts { get; private set; }

        /// <summary>
        /// Gets the total number of rootkit detections
        /// </summary>
        public int TotalRootkitDetections { get; private set; }

        /// <summary>
        /// Gets the event log collector
        /// </summary>
        public EventLogCollector EventLogCollector => _eventLogCollector;

        /// <summary>
        /// Gets the correlation engine
        /// </summary>
        public EventCorrelationEngine CorrelationEngine => _correlationEngine;

        /// <summary>
        /// Gets the threat intelligence manager
        /// </summary>
        public ThreatIntelligenceManager ThreatIntelligenceManager => _threatIntelligenceManager;

        /// <summary>
        /// Gets the rootkit detector
        /// </summary>
        public RootkitDetector RootkitDetector => _rootkitDetector;

        /// <summary>
        /// Initializes a new instance of the EventLogManager class
        /// </summary>
        /// <param name="enableRootkitDetection">Whether to enable rootkit detection</param>
        /// <param name="statusCheckIntervalMs">The status check interval in milliseconds</param>
        public EventLogManager(bool enableRootkitDetection = false, int statusCheckIntervalMs = 60000) // Default to 1 minute
        {
            StatusCheckIntervalMs = statusCheckIntervalMs;

            try
            {
                // Initialize components
                _eventLogCollector = new EventLogCollector();
                _threatIntelligenceManager = new ThreatIntelligenceManager();
                _correlationEngine = new EventCorrelationEngine(_eventLogCollector, _threatIntelligenceManager);

                if (enableRootkitDetection)
                {
                    _rootkitDetector = new RootkitDetector();
                    _rootkitDetector.RootkitDetected += RootkitDetector_RootkitDetected;
                    _rootkitDetector.ScanError += RootkitDetector_ScanError;
                }

                // Subscribe to events
                _eventLogCollector.EventLogEntriesCollected += EventLogCollector_EventLogEntriesCollected;
                _eventLogCollector.EventLogCollectionError += EventLogCollector_EventLogCollectionError;

                _correlationEngine.CorrelationAlert += CorrelationEngine_CorrelationAlert;
                _correlationEngine.CorrelationError += CorrelationEngine_CorrelationError;

                _threatIntelligenceManager.ThreatIntelligenceUpdated += ThreatIntelligenceManager_ThreatIntelligenceUpdated;
                _threatIntelligenceManager.ThreatFeedUpdateError += ThreatIntelligenceManager_ThreatFeedUpdateError;

                // Initialize status check timer
                _statusCheckTimer = new Timer(StatusCheckIntervalMs);
                _statusCheckTimer.Elapsed += StatusCheckTimer_Elapsed;
                _statusCheckTimer.AutoReset = true;

                _logger.LogInfo("EventLogManager initialized");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing EventLogManager: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error initializing EventLogManager");
                throw;
            }
        }

        /// <summary>
        /// Starts all components
        /// </summary>
        public void Start()
        {
            try
            {
                _logger.LogInfo("Starting EventLogManager components");

                // Start components
                _eventLogCollector.StartCollection();
                _threatIntelligenceManager.StartUpdates();
                _correlationEngine.Start();

                if (_rootkitDetector != null)
                {
                    _rootkitDetector.Start();
                }

                // Start status check timer
                _statusCheckTimer.Start();

                _logger.LogInfo("EventLogManager components started");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error starting EventLogManager components: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error starting EventLogManager components");
                OnErrorOccurred("Start", ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Stops all components
        /// </summary>
        public void Stop()
        {
            try
            {
                _logger.LogInfo("Stopping EventLogManager components");

                // Stop status check timer
                _statusCheckTimer.Stop();

                // Stop components
                _eventLogCollector.StopCollection();
                _threatIntelligenceManager.StopUpdates();
                _correlationEngine.Stop();

                if (_rootkitDetector != null)
                {
                    _rootkitDetector.Stop();
                }

                _logger.LogInfo("EventLogManager components stopped");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error stopping EventLogManager components: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error stopping EventLogManager components");
                OnErrorOccurred("Stop", ex.Message);
            }
        }

        /// <summary>
        /// Performs a status check of all components
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task<EventLogManagerStatus> CheckStatusAsync()
        {
            try
            {
                _logger.LogInfo("Checking EventLogManager status");

                var status = new EventLogManagerStatus
                {
                    CheckTime = DateTime.Now,
                    IsCollectionActive = IsCollectionActive,
                    IsCorrelationActive = IsCorrelationActive,
                    IsThreatIntelligenceActive = IsThreatIntelligenceActive,
                    IsRootkitDetectionActive = IsRootkitDetectionActive,
                    TotalCorrelationAlerts = TotalCorrelationAlerts,
                    TotalRootkitDetections = TotalRootkitDetections,
                    CollectedLogEntries = _eventLogCollector.TotalEntriesCollected,
                    LastCollectionTime = _eventLogCollector.LastCollectionTime,
                    LastThreatIntelligenceUpdateTime = _threatIntelligenceManager.LastUpdateTime,
                    LastRootkitScanTime = _rootkitDetector?.LastScanTime ?? DateTime.MinValue,
                    ActiveRules = _correlationEngine.ActiveRules.Count,
                    ConfiguredThreatFeeds = _threatIntelligenceManager.ConfiguredFeeds.Count
                };

                // Check for any errors
                if (_eventLogCollector.LastErrorMessage != null)
                {
                    status.Errors.Add(new EventLogManagerError
                    {
                        Component = "EventLogCollector",
                        ErrorMessage = _eventLogCollector.LastErrorMessage,
                        ErrorTime = _eventLogCollector.LastErrorTime
                    });
                }

                if (_correlationEngine.LastErrorMessage != null)
                {
                    status.Errors.Add(new EventLogManagerError
                    {
                        Component = "CorrelationEngine",
                        ErrorMessage = _correlationEngine.LastErrorMessage,
                        ErrorTime = _correlationEngine.LastErrorTime
                    });
                }

                if (_threatIntelligenceManager.LastErrorMessage != null)
                {
                    status.Errors.Add(new EventLogManagerError
                    {
                        Component = "ThreatIntelligenceManager",
                        ErrorMessage = _threatIntelligenceManager.LastErrorMessage,
                        ErrorTime = _threatIntelligenceManager.LastErrorTime
                    });
                }

                // Update last status check time
                LastStatusCheckTime = DateTime.Now;

                // Raise status check completed event
                OnStatusCheckCompleted(status);

                _logger.LogInfo("EventLogManager status check completed");

                return status;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking EventLogManager status: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error checking EventLogManager status");
                OnErrorOccurred("CheckStatus", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Performs a rootkit scan
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task<RootkitScanResult> ScanForRootkitsAsync()
        {
            if (_rootkitDetector == null)
            {
                _logger.LogWarning("Rootkit detection is not enabled");
                OnErrorOccurred("ScanForRootkits", "Rootkit detection is not enabled");
                return null;
            }

            try
            {
                _logger.LogInfo("Starting rootkit scan");
                return await _rootkitDetector.ScanAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for rootkits: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error scanning for rootkits");
                OnErrorOccurred("ScanForRootkits", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Updates threat intelligence feeds
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task UpdateThreatIntelligenceAsync()
        {
            try
            {
                _logger.LogInfo("Updating threat intelligence feeds");
                await _threatIntelligenceManager.UpdateAllFeedsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating threat intelligence feeds: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error updating threat intelligence feeds");
                OnErrorOccurred("UpdateThreatIntelligence", ex.Message);
            }
        }

        /// <summary>
        /// Adds a correlation rule
        /// </summary>
        /// <param name="rule">The correlation rule to add</param>
        public void AddCorrelationRule(CorrelationRule rule)
        {
            try
            {
                _correlationEngine.AddRule(rule);
                _logger.LogInfo($"Added correlation rule: {rule.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding correlation rule: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error adding correlation rule");
                OnErrorOccurred("AddCorrelationRule", ex.Message);
            }
        }

        /// <summary>
        /// Removes a correlation rule
        /// </summary>
        /// <param name="ruleName">The name of the correlation rule to remove</param>
        public void RemoveCorrelationRule(string ruleName)
        {
            try
            {
                _correlationEngine.RemoveRule(ruleName);
                _logger.LogInfo($"Removed correlation rule: {ruleName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removing correlation rule: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error removing correlation rule");
                OnErrorOccurred("RemoveCorrelationRule", ex.Message);
            }
        }

        /// <summary>
        /// Adds a threat feed
        /// </summary>
        /// <param name="feed">The threat feed to add</param>
        public void AddThreatFeed(ThreatFeed feed)
        {
            try
            {
                _threatIntelligenceManager.AddFeed(feed);
                _logger.LogInfo($"Added threat feed: {feed.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding threat feed: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error adding threat feed");
                OnErrorOccurred("AddThreatFeed", ex.Message);
            }
        }

        /// <summary>
        /// Removes a threat feed
        /// </summary>
        /// <param name="feedName">The name of the threat feed to remove</param>
        public void RemoveThreatFeed(string feedName)
        {
            try
            {
                _threatIntelligenceManager.RemoveFeed(feedName);
                _logger.LogInfo($"Removed threat feed: {feedName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removing threat feed: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error removing threat feed");
                OnErrorOccurred("RemoveThreatFeed", ex.Message);
            }
        }

        /// <summary>
        /// Adds an event log source
        /// </summary>
        /// <param name="logName">The name of the event log</param>
        public void AddEventLogSource(string logName)
        {
            try
            {
                _eventLogCollector.AddLogSource(logName);
                _logger.LogInfo($"Added event log source: {logName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding event log source: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error adding event log source");
                OnErrorOccurred("AddEventLogSource", ex.Message);
            }
        }

        /// <summary>
        /// Removes an event log source
        /// </summary>
        /// <param name="logName">The name of the event log to remove</param>
        public void RemoveEventLogSource(string logName)
        {
            try
            {
                _eventLogCollector.RemoveLogSource(logName);
                _logger.LogInfo($"Removed event log source: {logName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removing event log source: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error removing event log source");
                OnErrorOccurred("RemoveEventLogSource", ex.Message);
            }
        }

        /// <summary>
        /// Gets all correlation alerts
        /// </summary>
        /// <returns>A list of correlation alerts</returns>
        public List<CorrelationAlert> GetCorrelationAlerts()
        {
            try
            {
                return _correlationEngine.GetAlerts();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting correlation alerts: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error getting correlation alerts");
                OnErrorOccurred("GetCorrelationAlerts", ex.Message);
                return new List<CorrelationAlert>();
            }
        }

        /// <summary>
        /// Gets all rootkit detections
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        public List<RootkitDetection> GetRootkitDetections()
        {
            if (_rootkitDetector == null)
            {
                _logger.LogWarning("Rootkit detection is not enabled");
                return new List<RootkitDetection>();
            }

            try
            {
                // In a real implementation, this would retrieve detections from a storage mechanism
                // For this example, we'll just return an empty list
                return new List<RootkitDetection>();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting rootkit detections: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error getting rootkit detections");
                OnErrorOccurred("GetRootkitDetections", ex.Message);
                return new List<RootkitDetection>();
            }
        }

        /// <summary>
        /// Gets recent event log entries
        /// </summary>
        /// <param name="count">The number of entries to retrieve</param>
        /// <returns>A list of event log entries</returns>
        public List<EventLogEntry> GetRecentEventLogEntries(int count = 100)
        {
            try
            {
                return _eventLogCollector.GetRecentEntries(count);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting recent event log entries: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error getting recent event log entries");
                OnErrorOccurred("GetRecentEventLogEntries", ex.Message);
                return new List<EventLogEntry>();
            }
        }

        /// <summary>
        /// Handles the status check timer elapsed event
        /// </summary>
        private async void StatusCheckTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            _statusCheckTimer.Stop();

            try
            {
                await CheckStatusAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in status check timer: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error in status check timer");
            }
            finally
            {
                _statusCheckTimer.Start();
            }
        }

        /// <summary>
        /// Handles the event log entries collected event
        /// </summary>
        private void EventLogCollector_EventLogEntriesCollected(object sender, EventLogEntriesCollectedEventArgs e)
        {
            try
            {
                _logger.LogDebug($"Collected {e.Entries.Count} event log entries from {e.LogName}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling event log entries collected event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling event log entries collected event");
            }
        }

        /// <summary>
        /// Handles the event log collection error event
        /// </summary>
        private void EventLogCollector_EventLogCollectionError(object sender, EventLogCollectionErrorEventArgs e)
        {
            try
            {
                _logger.LogError($"Event log collection error for {e.LogName}: {e.ErrorMessage}");
                OnErrorOccurred("EventLogCollection", $"Error collecting from {e.LogName}: {e.ErrorMessage}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling event log collection error event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling event log collection error event");
            }
        }

        /// <summary>
        /// Handles the correlation alert event
        /// </summary>
        private void CorrelationEngine_CorrelationAlert(object sender, CorrelationAlertEventArgs e)
        {
            try
            {
                _logger.LogWarning($"Correlation alert: {e.Alert.RuleName} - {e.Alert.Description}");
                TotalCorrelationAlerts++;
                OnCorrelationAlertDetected(e.Alert);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling correlation alert event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling correlation alert event");
            }
        }

        /// <summary>
        /// Handles the correlation error event
        /// </summary>
        private void CorrelationEngine_CorrelationError(object sender, CorrelationErrorEventArgs e)
        {
            try
            {
                _logger.LogError($"Correlation error for rule {e.RuleName}: {e.ErrorMessage}");
                OnErrorOccurred("Correlation", $"Error in rule {e.RuleName}: {e.ErrorMessage}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling correlation error event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling correlation error event");
            }
        }

        /// <summary>
        /// Handles the threat intelligence updated event
        /// </summary>
        private void ThreatIntelligenceManager_ThreatIntelligenceUpdated(object sender, ThreatIntelligenceUpdatedEventArgs e)
        {
            try
            {
                _logger.LogInfo($"Threat intelligence updated: {e.FeedName} - {e.ItemsUpdated} items");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling threat intelligence updated event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling threat intelligence updated event");
            }
        }

        /// <summary>
        /// Handles the threat feed update error event
        /// </summary>
        private void ThreatIntelligenceManager_ThreatFeedUpdateError(object sender, ThreatFeedUpdateErrorEventArgs e)
        {
            try
            {
                _logger.LogError($"Threat feed update error for {e.FeedName}: {e.ErrorMessage}");
                OnErrorOccurred("ThreatFeedUpdate", $"Error updating feed {e.FeedName}: {e.ErrorMessage}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling threat feed update error event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling threat feed update error event");
            }
        }

        /// <summary>
        /// Handles the rootkit detected event
        /// </summary>
        private void RootkitDetector_RootkitDetected(object sender, RootkitDetectionEventArgs e)
        {
            try
            {
                _logger.LogWarning($"Rootkit detected: {e.Detection.Type} - {e.Detection.Description}");
                TotalRootkitDetections++;
                OnRootkitDetected(e.Detection);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling rootkit detected event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling rootkit detected event");
            }
        }

        /// <summary>
        /// Handles the rootkit scan error event
        /// </summary>
        private void RootkitDetector_ScanError(object sender, RootkitScanErrorEventArgs e)
        {
            try
            {
                _logger.LogError($"Rootkit scan error for {e.ScanType}: {e.ErrorMessage}");
                OnErrorOccurred("RootkitScan", $"Error in {e.ScanType} scan: {e.ErrorMessage}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling rootkit scan error event: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error handling rootkit scan error event");
            }
        }

        /// <summary>
        /// Raises the CorrelationAlertDetected event
        /// </summary>
        /// <param name="alert">The correlation alert</param>
        protected virtual void OnCorrelationAlertDetected(CorrelationAlert alert)
        {
            CorrelationAlertDetected?.Invoke(this, new CorrelationAlertEventArgs(alert));
        }

        /// <summary>
        /// Raises the RootkitDetected event
        /// </summary>
        /// <param name="detection">The rootkit detection</param>
        protected virtual void OnRootkitDetected(RootkitDetection detection)
        {
            RootkitDetected?.Invoke(this, new RootkitDetectionEventArgs(detection));
        }

        /// <summary>
        /// Raises the StatusCheckCompleted event
        /// </summary>
        /// <param name="status">The event log manager status</param>
        protected virtual void OnStatusCheckCompleted(EventLogManagerStatus status)
        {
            StatusCheckCompleted?.Invoke(this, new EventLogManagerStatusEventArgs(status));
        }

        /// <summary>
        /// Raises the ErrorOccurred event
        /// </summary>
        /// <param name="component">The component where the error occurred</param>
        /// <param name="errorMessage">The error message</param>
        protected virtual void OnErrorOccurred(string component, string errorMessage)
        {
            ErrorOccurred?.Invoke(this, new EventLogManagerErrorEventArgs(component, errorMessage));
        }
    }

    /// <summary>
    /// Represents the status of the event log manager
    /// </summary>
    public class EventLogManagerStatus
    {
        /// <summary>
        /// Gets or sets the check time
        /// </summary>
        public DateTime CheckTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the event log collection is active
        /// </summary>
        public bool IsCollectionActive { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the correlation engine is active
        /// </summary>
        public bool IsCorrelationActive { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the threat intelligence manager is active
        /// </summary>
        public bool IsThreatIntelligenceActive { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the rootkit detector is active
        /// </summary>
        public bool IsRootkitDetectionActive { get; set; }

        /// <summary>
        /// Gets or sets the total number of correlation alerts
        /// </summary>
        public int TotalCorrelationAlerts { get; set; }

        /// <summary>
        /// Gets or sets the total number of rootkit detections
        /// </summary>
        public int TotalRootkitDetections { get; set; }

        /// <summary>
        /// Gets or sets the total number of collected log entries
        /// </summary>
        public int CollectedLogEntries { get; set; }

        /// <summary>
        /// Gets or sets the last collection time
        /// </summary>
        public DateTime LastCollectionTime { get; set; }

        /// <summary>
        /// Gets or sets the last threat intelligence update time
        /// </summary>
        public DateTime LastThreatIntelligenceUpdateTime { get; set; }

        /// <summary>
        /// Gets or sets the last rootkit scan time
        /// </summary>
        public DateTime LastRootkitScanTime { get; set; }

        /// <summary>
        /// Gets or sets the number of active correlation rules
        /// </summary>
        public int ActiveRules { get; set; }

        /// <summary>
        /// Gets or sets the number of configured threat feeds
        /// </summary>
        public int ConfiguredThreatFeeds { get; set; }

        /// <summary>
        /// Gets or sets the list of errors
        /// </summary>
        public List<EventLogManagerError> Errors { get; set; } = new List<EventLogManagerError>();
    }

    /// <summary>
    /// Represents an error in the event log manager
    /// </summary>
    public class EventLogManagerError
    {
        /// <summary>
        /// Gets or sets the component where the error occurred
        /// </summary>
        public string Component { get; set; }

        /// <summary>
        /// Gets or sets the error message
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets the error time
        /// </summary>
        public DateTime ErrorTime { get; set; }
    }

    /// <summary>
    /// Event arguments for the StatusCheckCompleted event
    /// </summary>
    public class EventLogManagerStatusEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the event log manager status
        /// </summary>
        public EventLogManagerStatus Status { get; }

        /// <summary>
        /// Initializes a new instance of the EventLogManagerStatusEventArgs class
        /// </summary>
        /// <param name="status">The event log manager status</param>
        public EventLogManagerStatusEventArgs(EventLogManagerStatus status)
        {
            Status = status;
        }
    }

    /// <summary>
    /// Event arguments for the ErrorOccurred event
    /// </summary>
    public class EventLogManagerErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the component where the error occurred
        /// </summary>
        public string Component { get; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Gets the error time
        /// </summary>
        public DateTime ErrorTime { get; }

        /// <summary>
        /// Initializes a new instance of the EventLogManagerErrorEventArgs class
        /// </summary>
        /// <param name="component">The component where the error occurred</param>
        /// <param name="errorMessage">The error message</param>
        public EventLogManagerErrorEventArgs(string component, string errorMessage)
        {
            Component = component;
            ErrorMessage = errorMessage;
            ErrorTime = DateTime.Now;
        }
    }
}