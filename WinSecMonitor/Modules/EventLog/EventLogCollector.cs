using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using System.Timers;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.EventLog
{
    /// <summary>
    /// Collects and processes Windows event logs from Security, System, Application, and custom sources
    /// </summary>
    public class EventLogCollector
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly Timer _collectionTimer;
        private readonly Dictionary<string, DateTime> _lastReadTimes = new Dictionary<string, DateTime>();
        private readonly List<string> _logSources = new List<string>();
        private readonly int _maxEventsPerCollection;
        private readonly int _maxHistoricalDays;
        private bool _isCollecting = false;

        /// <summary>
        /// Event raised when new log entries are collected
        /// </summary>
        public event EventHandler<EventLogEntriesCollectedEventArgs> EventLogEntriesCollected;

        /// <summary>
        /// Event raised when an error occurs during log collection
        /// </summary>
        public event EventHandler<EventLogCollectionErrorEventArgs> EventLogCollectionError;

        /// <summary>
        /// Gets or sets the collection interval in milliseconds
        /// </summary>
        public int CollectionIntervalMs { get; set; }

        /// <summary>
        /// Gets a value indicating whether log collection is currently active
        /// </summary>
        public bool IsCollecting => _isCollecting;

        /// <summary>
        /// Gets the list of log sources being monitored
        /// </summary>
        public IReadOnlyList<string> LogSources => _logSources.AsReadOnly();

        /// <summary>
        /// Gets the last read times for each log source
        /// </summary>
        public IReadOnlyDictionary<string, DateTime> LastReadTimes => _lastReadTimes;

        /// <summary>
        /// Initializes a new instance of the EventLogCollector class
        /// </summary>
        /// <param name="collectionIntervalMs">Collection interval in milliseconds</param>
        /// <param name="maxEventsPerCollection">Maximum number of events to collect per interval</param>
        /// <param name="maxHistoricalDays">Maximum number of days to look back for historical events</param>
        public EventLogCollector(int collectionIntervalMs = 30000, int maxEventsPerCollection = 1000, int maxHistoricalDays = 7)
        {
            CollectionIntervalMs = collectionIntervalMs;
            _maxEventsPerCollection = maxEventsPerCollection;
            _maxHistoricalDays = maxHistoricalDays;

            // Initialize default log sources
            _logSources.Add("Security");
            _logSources.Add("System");
            _logSources.Add("Application");

            // Initialize last read times to now minus maxHistoricalDays
            var startTime = DateTime.Now.AddDays(-_maxHistoricalDays);
            foreach (var source in _logSources)
            {
                _lastReadTimes[source] = startTime;
            }

            // Initialize collection timer
            _collectionTimer = new Timer(CollectionIntervalMs);
            _collectionTimer.Elapsed += CollectionTimer_Elapsed;
            _collectionTimer.AutoReset = true;

            _logger.LogInfo($"EventLogCollector initialized with {_logSources.Count} log sources");
        }

        /// <summary>
        /// Starts collecting event logs
        /// </summary>
        public void StartCollection()
        {
            if (!_isCollecting)
            {
                _isCollecting = true;
                _collectionTimer.Start();
                _logger.LogInfo("Event log collection started");
            }
        }

        /// <summary>
        /// Stops collecting event logs
        /// </summary>
        public void StopCollection()
        {
            if (_isCollecting)
            {
                _isCollecting = false;
                _collectionTimer.Stop();
                _logger.LogInfo("Event log collection stopped");
            }
        }

        /// <summary>
        /// Adds a custom log source to monitor
        /// </summary>
        /// <param name="logSource">Name of the log source</param>
        public void AddLogSource(string logSource)
        {
            if (!string.IsNullOrWhiteSpace(logSource) && !_logSources.Contains(logSource))
            {
                try
                {
                    // Verify the log source exists
                    using (var reader = new EventLogReader(new EventLogQuery(logSource, PathType.LogName)))
                    {
                        // Just testing if we can read from this source
                        var testEvent = reader.ReadEvent();
                    }

                    _logSources.Add(logSource);
                    _lastReadTimes[logSource] = DateTime.Now.AddDays(-_maxHistoricalDays);
                    _logger.LogInfo($"Added log source: {logSource}");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to add log source {logSource}: {ex.Message}");
                    _exceptionHandler.HandleException(ex, $"Failed to add log source {logSource}");
                    OnEventLogCollectionError(logSource, $"Failed to add log source: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Removes a log source from monitoring
        /// </summary>
        /// <param name="logSource">Name of the log source</param>
        public void RemoveLogSource(string logSource)
        {
            if (_logSources.Contains(logSource) && 
                logSource != "Security" && 
                logSource != "System" && 
                logSource != "Application")
            {
                _logSources.Remove(logSource);
                _lastReadTimes.Remove(logSource);
                _logger.LogInfo($"Removed log source: {logSource}");
            }
        }

        /// <summary>
        /// Collects event logs from all sources
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task<Dictionary<string, List<EventLogEntry>>> CollectLogsAsync()
        {
            var allEntries = new Dictionary<string, List<EventLogEntry>>();

            foreach (var source in _logSources.ToList()) // Use ToList to avoid collection modified exception
            {
                try
                {
                    var entries = await CollectLogsFromSourceAsync(source);
                    if (entries.Count > 0)
                    {
                        allEntries[source] = entries;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error collecting logs from {source}: {ex.Message}");
                    _exceptionHandler.HandleException(ex, $"Error collecting logs from {source}");
                    OnEventLogCollectionError(source, ex.Message);
                }
            }

            if (allEntries.Count > 0)
            {
                OnEventLogEntriesCollected(allEntries);
            }

            return allEntries;
        }

        /// <summary>
        /// Collects event logs from a specific source
        /// </summary>
        /// <param name="source">The log source to collect from</param>
        /// <returns>A list of collected event log entries</returns>
        private async Task<List<EventLogEntry>> CollectLogsFromSourceAsync(string source)
        {
            var entries = new List<EventLogEntry>();

            await Task.Run(() =>
            {
                try
                {
                    var lastReadTime = _lastReadTimes[source];
                    var query = new EventLogQuery(source, PathType.LogName, 
                        $"*[System[TimeCreated[@SystemTime >= '{lastReadTime.ToUniversalTime():o}']]]");

                    using (var reader = new EventLogReader(query))
                    {
                        var count = 0;
                        var latestTimestamp = lastReadTime;

                        for (var eventInstance = reader.ReadEvent(); 
                             eventInstance != null && count < _maxEventsPerCollection; 
                             eventInstance = reader.ReadEvent())
                        {
                            using (eventInstance)
                            {
                                var entry = new EventLogEntry
                                {
                                    Source = source,
                                    EventId = eventInstance.Id,
                                    Level = (EventLogEntryLevel)eventInstance.Level.GetValueOrDefault(),
                                    TimeCreated = eventInstance.TimeCreated.GetValueOrDefault(),
                                    MachineName = eventInstance.MachineName,
                                    Message = eventInstance.FormatDescription(),
                                    ProviderName = eventInstance.ProviderName,
                                    TaskCategory = eventInstance.Task.GetValueOrDefault(),
                                    Properties = ExtractProperties(eventInstance)
                                };

                                entries.Add(entry);
                                count++;

                                if (entry.TimeCreated > latestTimestamp)
                                {
                                    latestTimestamp = entry.TimeCreated;
                                }
                            }
                        }

                        // Update last read time if we found any events
                        if (latestTimestamp > lastReadTime)
                        {
                            _lastReadTimes[source] = latestTimestamp.AddMilliseconds(1); // Add 1ms to avoid duplicates
                        }
                    }
                }
                catch (EventLogNotFoundException)
                {
                    _logger.LogWarning($"Event log source not found: {source}");
                    OnEventLogCollectionError(source, "Event log source not found");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogError($"Access denied to event log {source}: {ex.Message}");
                    OnEventLogCollectionError(source, $"Access denied to event log: {ex.Message}");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error reading from event log {source}: {ex.Message}");
                    OnEventLogCollectionError(source, $"Error reading from event log: {ex.Message}");
                }
            });

            return entries;
        }

        /// <summary>
        /// Extracts properties from an event record
        /// </summary>
        /// <param name="eventRecord">The event record to extract properties from</param>
        /// <returns>A dictionary of property names and values</returns>
        private Dictionary<string, string> ExtractProperties(EventRecord eventRecord)
        {
            var properties = new Dictionary<string, string>();

            try
            {
                if (eventRecord.Properties != null)
                {
                    int index = 0;
                    foreach (var prop in eventRecord.Properties)
                    {
                        if (prop != null && prop.Value != null)
                        {
                            properties[$"Param{index}"] = prop.Value.ToString();
                        }
                        index++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error extracting event properties: {ex.Message}");
            }

            return properties;
        }

        /// <summary>
        /// Handles the timer elapsed event
        /// </summary>
        private async void CollectionTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            _collectionTimer.Stop();

            try
            {
                await CollectLogsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in collection timer: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error in event log collection timer");
            }
            finally
            {
                if (_isCollecting)
                {
                    _collectionTimer.Start();
                }
            }
        }

        /// <summary>
        /// Raises the EventLogEntriesCollected event
        /// </summary>
        /// <param name="entries">The collected event log entries</param>
        protected virtual void OnEventLogEntriesCollected(Dictionary<string, List<EventLogEntry>> entries)
        {
            EventLogEntriesCollected?.Invoke(this, new EventLogEntriesCollectedEventArgs(entries));
        }

        /// <summary>
        /// Raises the EventLogCollectionError event
        /// </summary>
        /// <param name="source">The log source that had an error</param>
        /// <param name="errorMessage">The error message</param>
        protected virtual void OnEventLogCollectionError(string source, string errorMessage)
        {
            EventLogCollectionError?.Invoke(this, new EventLogCollectionErrorEventArgs(source, errorMessage));
        }
    }

    /// <summary>
    /// Represents a Windows event log entry
    /// </summary>
    public class EventLogEntry
    {
        /// <summary>
        /// Gets or sets the source of the event log
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// Gets or sets the event ID
        /// </summary>
        public int EventId { get; set; }

        /// <summary>
        /// Gets or sets the event level
        /// </summary>
        public EventLogEntryLevel Level { get; set; }

        /// <summary>
        /// Gets or sets the time the event was created
        /// </summary>
        public DateTime TimeCreated { get; set; }

        /// <summary>
        /// Gets or sets the machine name
        /// </summary>
        public string MachineName { get; set; }

        /// <summary>
        /// Gets or sets the event message
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// Gets or sets the provider name
        /// </summary>
        public string ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the task category
        /// </summary>
        public int TaskCategory { get; set; }

        /// <summary>
        /// Gets or sets the event properties
        /// </summary>
        public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
    }

    /// <summary>
    /// Represents the level of an event log entry
    /// </summary>
    public enum EventLogEntryLevel
    {
        /// <summary>
        /// Verbose level
        /// </summary>
        Verbose = 5,

        /// <summary>
        /// Information level
        /// </summary>
        Information = 4,

        /// <summary>
        /// Warning level
        /// </summary>
        Warning = 3,

        /// <summary>
        /// Error level
        /// </summary>
        Error = 2,

        /// <summary>
        /// Critical level
        /// </summary>
        Critical = 1,

        /// <summary>
        /// LogAlways level
        /// </summary>
        LogAlways = 0
    }

    /// <summary>
    /// Event arguments for the EventLogEntriesCollected event
    /// </summary>
    public class EventLogEntriesCollectedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the collected event log entries
        /// </summary>
        public Dictionary<string, List<EventLogEntry>> Entries { get; }

        /// <summary>
        /// Initializes a new instance of the EventLogEntriesCollectedEventArgs class
        /// </summary>
        /// <param name="entries">The collected event log entries</param>
        public EventLogEntriesCollectedEventArgs(Dictionary<string, List<EventLogEntry>> entries)
        {
            Entries = entries;
        }
    }

    /// <summary>
    /// Event arguments for the EventLogCollectionError event
    /// </summary>
    public class EventLogCollectionErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the log source that had an error
        /// </summary>
        public string Source { get; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the EventLogCollectionErrorEventArgs class
        /// </summary>
        /// <param name="source">The log source that had an error</param>
        /// <param name="errorMessage">The error message</param>
        public EventLogCollectionErrorEventArgs(string source, string errorMessage)
        {
            Source = source;
            ErrorMessage = errorMessage;
        }
    }
}