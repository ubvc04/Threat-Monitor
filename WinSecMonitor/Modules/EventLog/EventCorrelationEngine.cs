using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Timers;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.EventLog
{
    /// <summary>
    /// Engine for correlating multiple events to detect complex attack patterns
    /// </summary>
    public class EventCorrelationEngine
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly EventLogCollector _eventLogCollector;
        private readonly ThreatIntelligenceManager _threatIntelligenceManager;
        private readonly Timer _correlationTimer;
        private readonly List<CorrelationRule> _correlationRules = new List<CorrelationRule>();
        private readonly Dictionary<string, List<EventLogEntry>> _eventBuffer = new Dictionary<string, List<EventLogEntry>>();
        private readonly int _eventBufferMaxSize;
        private readonly int _eventBufferMaxAge;

        /// <summary>
        /// Event raised when a correlation alert is triggered
        /// </summary>
        public event EventHandler<CorrelationAlertEventArgs> CorrelationAlertTriggered;

        /// <summary>
        /// Event raised when a correlation error occurs
        /// </summary>
        public event EventHandler<CorrelationErrorEventArgs> CorrelationError;

        /// <summary>
        /// Gets the list of correlation rules
        /// </summary>
        public IReadOnlyList<CorrelationRule> CorrelationRules => _correlationRules;

        /// <summary>
        /// Gets or sets the correlation interval in milliseconds
        /// </summary>
        public int CorrelationIntervalMs { get; set; }

        /// <summary>
        /// Gets a value indicating whether correlation is running
        /// </summary>
        public bool IsRunning => _correlationTimer.Enabled;

        /// <summary>
        /// Gets the last correlation time
        /// </summary>
        public DateTime LastCorrelationTime { get; private set; }

        /// <summary>
        /// Gets the total number of correlation alerts triggered
        /// </summary>
        public int TotalAlertsTriggered { get; private set; }

        /// <summary>
        /// Initializes a new instance of the EventCorrelationEngine class
        /// </summary>
        /// <param name="eventLogCollector">The event log collector</param>
        /// <param name="threatIntelligenceManager">The threat intelligence manager</param>
        /// <param name="correlationIntervalMs">The correlation interval in milliseconds</param>
        /// <param name="eventBufferMaxSize">The maximum number of events to keep in the buffer per source</param>
        /// <param name="eventBufferMaxAge">The maximum age of events to keep in the buffer in minutes</param>
        public EventCorrelationEngine(
            EventLogCollector eventLogCollector,
            ThreatIntelligenceManager threatIntelligenceManager,
            int correlationIntervalMs = 30000,
            int eventBufferMaxSize = 1000,
            int eventBufferMaxAge = 60)
        {
            _eventLogCollector = eventLogCollector ?? throw new ArgumentNullException(nameof(eventLogCollector));
            _threatIntelligenceManager = threatIntelligenceManager ?? throw new ArgumentNullException(nameof(threatIntelligenceManager));
            CorrelationIntervalMs = correlationIntervalMs;
            _eventBufferMaxSize = eventBufferMaxSize;
            _eventBufferMaxAge = eventBufferMaxAge;

            // Initialize correlation timer
            _correlationTimer = new Timer(CorrelationIntervalMs);
            _correlationTimer.Elapsed += CorrelationTimer_Elapsed;
            _correlationTimer.AutoReset = true;

            // Subscribe to event log collector events
            _eventLogCollector.EventLogEntriesCollected += EventLogCollector_EventLogEntriesCollected;
            _eventLogCollector.EventLogCollectionError += EventLogCollector_EventLogCollectionError;

            // Initialize default correlation rules
            InitializeDefaultRules();

            _logger.LogInfo("EventCorrelationEngine initialized");
        }

        /// <summary>
        /// Starts the correlation engine
        /// </summary>
        public void Start()
        {
            if (!_correlationTimer.Enabled)
            {
                _correlationTimer.Start();
                _logger.LogInfo("Event correlation engine started");
            }
        }

        /// <summary>
        /// Stops the correlation engine
        /// </summary>
        public void Stop()
        {
            if (_correlationTimer.Enabled)
            {
                _correlationTimer.Stop();
                _logger.LogInfo("Event correlation engine stopped");
            }
        }

        /// <summary>
        /// Adds a correlation rule
        /// </summary>
        /// <param name="rule">The rule to add</param>
        public void AddRule(CorrelationRule rule)
        {
            if (rule == null)
            {
                throw new ArgumentNullException(nameof(rule));
            }

            _correlationRules.Add(rule);
            _logger.LogInfo($"Added correlation rule: {rule.Name}");
        }

        /// <summary>
        /// Removes a correlation rule
        /// </summary>
        /// <param name="ruleName">The name of the rule to remove</param>
        /// <returns>True if the rule was removed, false otherwise</returns>
        public bool RemoveRule(string ruleName)
        {
            var rule = _correlationRules.FirstOrDefault(r => r.Name == ruleName);
            if (rule != null)
            {
                _correlationRules.Remove(rule);
                _logger.LogInfo($"Removed correlation rule: {ruleName}");
                return true;
            }

            return false;
        }

        /// <summary>
        /// Clears all correlation rules
        /// </summary>
        public void ClearRules()
        {
            _correlationRules.Clear();
            _logger.LogInfo("Cleared all correlation rules");
        }

        /// <summary>
        /// Clears the event buffer
        /// </summary>
        public void ClearEventBuffer()
        {
            lock (_eventBuffer)
            {
                _eventBuffer.Clear();
            }

            _logger.LogInfo("Cleared event buffer");
        }

        /// <summary>
        /// Performs correlation on the event buffer
        /// </summary>
        public void PerformCorrelation()
        {
            try
            {
                _logger.LogInfo("Performing event correlation");

                // Clean up old events first
                CleanupEventBuffer();

                // Apply each correlation rule
                foreach (var rule in _correlationRules)
                {
                    try
                    {
                        ApplyCorrelationRule(rule);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error applying correlation rule {rule.Name}: {ex.Message}");
                        OnCorrelationError(rule.Name, ex.Message);
                    }
                }

                LastCorrelationTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error performing correlation: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error performing event correlation");
            }
        }

        /// <summary>
        /// Applies a correlation rule to the event buffer
        /// </summary>
        /// <param name="rule">The rule to apply</param>
        private void ApplyCorrelationRule(CorrelationRule rule)
        {
            // Skip disabled rules
            if (!rule.IsEnabled)
            {
                return;
            }

            _logger.LogDebug($"Applying correlation rule: {rule.Name}");

            // Get events for the sources specified in the rule
            var relevantEvents = new Dictionary<string, List<EventLogEntry>>();
            lock (_eventBuffer)
            {
                foreach (var source in rule.EventSources)
                {
                    if (_eventBuffer.TryGetValue(source, out var events))
                    {
                        relevantEvents[source] = new List<EventLogEntry>(events);
                    }
                }
            }

            // Skip if we don't have events for all required sources
            if (rule.RequireAllSources && relevantEvents.Count < rule.EventSources.Count)
            {
                return;
            }

            // Apply the rule based on its type
            switch (rule.Type)
            {
                case CorrelationRuleType.SequentialEvents:
                    ApplySequentialEventsRule(rule, relevantEvents);
                    break;

                case CorrelationRuleType.ThresholdBased:
                    ApplyThresholdBasedRule(rule, relevantEvents);
                    break;

                case CorrelationRuleType.PatternMatching:
                    ApplyPatternMatchingRule(rule, relevantEvents);
                    break;

                case CorrelationRuleType.ThreatIntelligence:
                    ApplyThreatIntelligenceRule(rule, relevantEvents);
                    break;
            }
        }

        /// <summary>
        /// Applies a sequential events correlation rule
        /// </summary>
        /// <param name="rule">The rule to apply</param>
        /// <param name="relevantEvents">The relevant events</param>
        private void ApplySequentialEventsRule(CorrelationRule rule, Dictionary<string, List<EventLogEntry>> relevantEvents)
        {
            // This rule type looks for a specific sequence of events across different sources
            // within a specified time window

            // Get all events from all sources and sort by timestamp
            var allEvents = new List<EventLogEntry>();
            foreach (var events in relevantEvents.Values)
            {
                allEvents.AddRange(events);
            }

            allEvents = allEvents.OrderBy(e => e.Timestamp).ToList();

            // Check for the sequence pattern
            var sequencePatterns = rule.Parameters.GetValueOrDefault("sequence", "").Split('|');
            if (sequencePatterns.Length == 0)
            {
                return;
            }

            // Get the time window in seconds
            if (!int.TryParse(rule.Parameters.GetValueOrDefault("timeWindowSeconds", "300"), out var timeWindowSeconds))
            {
                timeWindowSeconds = 300; // Default to 5 minutes
            }

            // Find sequences that match the pattern
            var matchedSequences = new List<List<EventLogEntry>>();
            var currentSequence = new List<EventLogEntry>();
            var patternIndex = 0;

            foreach (var evt in allEvents)
            {
                // Check if this event matches the current pattern in the sequence
                if (MatchesPattern(evt, sequencePatterns[patternIndex]))
                {
                    // If this is the first event in the sequence or it's within the time window
                    if (currentSequence.Count == 0 ||
                        (evt.Timestamp - currentSequence[0].Timestamp).TotalSeconds <= timeWindowSeconds)
                    {
                        currentSequence.Add(evt);
                        patternIndex++;

                        // If we've matched the entire sequence
                        if (patternIndex >= sequencePatterns.Length)
                        {
                            matchedSequences.Add(new List<EventLogEntry>(currentSequence));
                            currentSequence.Clear();
                            patternIndex = 0;
                        }
                    }
                    else
                    {
                        // Time window exceeded, start a new sequence
                        currentSequence.Clear();
                        currentSequence.Add(evt);
                        patternIndex = 1;
                    }
                }
            }

            // Trigger alerts for each matched sequence
            foreach (var sequence in matchedSequences)
            {
                var alert = new CorrelationAlert
                {
                    RuleName = rule.Name,
                    Severity = rule.Severity,
                    Timestamp = DateTime.Now,
                    Description = rule.Description,
                    RelatedEvents = sequence
                };

                TriggerAlert(alert);
            }
        }

        /// <summary>
        /// Applies a threshold-based correlation rule
        /// </summary>
        /// <param name="rule">The rule to apply</param>
        /// <param name="relevantEvents">The relevant events</param>
        private void ApplyThresholdBasedRule(CorrelationRule rule, Dictionary<string, List<EventLogEntry>> relevantEvents)
        {
            // This rule type looks for a threshold of similar events within a time window

            // Get the threshold count
            if (!int.TryParse(rule.Parameters.GetValueOrDefault("threshold", "5"), out var threshold))
            {
                threshold = 5; // Default threshold
            }

            // Get the time window in seconds
            if (!int.TryParse(rule.Parameters.GetValueOrDefault("timeWindowSeconds", "300"), out var timeWindowSeconds))
            {
                timeWindowSeconds = 300; // Default to 5 minutes
            }

            // Get the pattern to match
            var pattern = rule.Parameters.GetValueOrDefault("pattern", "");
            if (string.IsNullOrEmpty(pattern))
            {
                return;
            }

            // Count matching events within the time window for each source
            var now = DateTime.Now;
            var matchingSets = new List<List<EventLogEntry>>();

            foreach (var source in relevantEvents.Keys)
            {
                var events = relevantEvents[source];
                var recentEvents = events.Where(e => (now - e.Timestamp).TotalSeconds <= timeWindowSeconds).ToList();

                // Group events by the pattern (e.g., by event ID or message pattern)
                var groupedEvents = new Dictionary<string, List<EventLogEntry>>();

                foreach (var evt in recentEvents)
                {
                    if (MatchesPattern(evt, pattern))
                    {
                        var key = GetEventGroupKey(evt, rule.Parameters.GetValueOrDefault("groupBy", "EventID"));
                        if (!groupedEvents.ContainsKey(key))
                        {
                            groupedEvents[key] = new List<EventLogEntry>();
                        }

                        groupedEvents[key].Add(evt);
                    }
                }

                // Check if any group exceeds the threshold
                foreach (var group in groupedEvents.Values)
                {
                    if (group.Count >= threshold)
                    {
                        matchingSets.Add(group);
                    }
                }
            }

            // Trigger alerts for each matching set
            foreach (var matchingSet in matchingSets)
            {
                var alert = new CorrelationAlert
                {
                    RuleName = rule.Name,
                    Severity = rule.Severity,
                    Timestamp = DateTime.Now,
                    Description = $"{rule.Description} ({matchingSet.Count} events)",
                    RelatedEvents = matchingSet
                };

                TriggerAlert(alert);
            }
        }

        /// <summary>
        /// Applies a pattern matching correlation rule
        /// </summary>
        /// <param name="rule">The rule to apply</param>
        /// <param name="relevantEvents">The relevant events</param>
        private void ApplyPatternMatchingRule(CorrelationRule rule, Dictionary<string, List<EventLogEntry>> relevantEvents)
        {
            // This rule type looks for specific patterns across different event sources

            // Get the patterns to match for each source
            var sourcePatterns = new Dictionary<string, string>();
            foreach (var source in rule.EventSources)
            {
                var pattern = rule.Parameters.GetValueOrDefault($"pattern_{source}", "");
                if (!string.IsNullOrEmpty(pattern))
                {
                    sourcePatterns[source] = pattern;
                }
            }

            // Get the time window in seconds
            if (!int.TryParse(rule.Parameters.GetValueOrDefault("timeWindowSeconds", "300"), out var timeWindowSeconds))
            {
                timeWindowSeconds = 300; // Default to 5 minutes
            }

            // Find matching events for each source
            var now = DateTime.Now;
            var matchingEventsBySource = new Dictionary<string, List<EventLogEntry>>();

            foreach (var source in sourcePatterns.Keys)
            {
                if (relevantEvents.TryGetValue(source, out var events))
                {
                    var pattern = sourcePatterns[source];
                    var recentEvents = events.Where(e => (now - e.Timestamp).TotalSeconds <= timeWindowSeconds).ToList();
                    var matchingEvents = recentEvents.Where(e => MatchesPattern(e, pattern)).ToList();

                    if (matchingEvents.Count > 0)
                    {
                        matchingEventsBySource[source] = matchingEvents;
                    }
                }
            }

            // Check if we have matches for all required sources
            if (rule.RequireAllSources && matchingEventsBySource.Count < sourcePatterns.Count)
            {
                return;
            }

            // If we have matches for at least one source, trigger an alert
            if (matchingEventsBySource.Count > 0)
            {
                var allMatchingEvents = new List<EventLogEntry>();
                foreach (var events in matchingEventsBySource.Values)
                {
                    allMatchingEvents.AddRange(events);
                }

                var alert = new CorrelationAlert
                {
                    RuleName = rule.Name,
                    Severity = rule.Severity,
                    Timestamp = DateTime.Now,
                    Description = rule.Description,
                    RelatedEvents = allMatchingEvents
                };

                TriggerAlert(alert);
            }
        }

        /// <summary>
        /// Applies a threat intelligence correlation rule
        /// </summary>
        /// <param name="rule">The rule to apply</param>
        /// <param name="relevantEvents">The relevant events</param>
        private void ApplyThreatIntelligenceRule(CorrelationRule rule, Dictionary<string, List<EventLogEntry>> relevantEvents)
        {
            // This rule type correlates events with threat intelligence data

            // Get the time window in seconds
            if (!int.TryParse(rule.Parameters.GetValueOrDefault("timeWindowSeconds", "3600"), out var timeWindowSeconds))
            {
                timeWindowSeconds = 3600; // Default to 1 hour
            }

            // Get the threat type to check
            var threatType = rule.Parameters.GetValueOrDefault("threatType", "ip");

            // Find events within the time window
            var now = DateTime.Now;
            var recentEvents = new List<EventLogEntry>();
            foreach (var events in relevantEvents.Values)
            {
                recentEvents.AddRange(events.Where(e => (now - e.Timestamp).TotalSeconds <= timeWindowSeconds));
            }

            // Match events against threat intelligence
            var matchingEvents = new List<EventLogEntry>();
            foreach (var evt in recentEvents)
            {
                switch (threatType.ToLower())
                {
                    case "ip":
                        // Extract IPs from the event message
                        var ips = ExtractIPsFromEvent(evt);
                        foreach (var ip in ips)
                        {
                            if (_threatIntelligenceManager.IsMaliciousIP(ip))
                            {
                                matchingEvents.Add(evt);
                                break;
                            }
                        }
                        break;

                    case "hash":
                        // Extract hashes from the event message
                        var hashes = ExtractHashesFromEvent(evt);
                        foreach (var hash in hashes)
                        {
                            if (_threatIntelligenceManager.IsMalwareHash(hash))
                            {
                                matchingEvents.Add(evt);
                                break;
                            }
                        }
                        break;

                    case "cve":
                        // Extract CVEs from the event message
                        var cves = ExtractCVEsFromEvent(evt);
                        foreach (var cve in cves)
                        {
                            if (_threatIntelligenceManager.GetCVEInfo(cve) != null)
                            {
                                matchingEvents.Add(evt);
                                break;
                            }
                        }
                        break;
                }
            }

            // Trigger an alert if we found matching events
            if (matchingEvents.Count > 0)
            {
                var alert = new CorrelationAlert
                {
                    RuleName = rule.Name,
                    Severity = rule.Severity,
                    Timestamp = DateTime.Now,
                    Description = $"{rule.Description} ({matchingEvents.Count} events)",
                    RelatedEvents = matchingEvents
                };

                TriggerAlert(alert);
            }
        }

        /// <summary>
        /// Extracts IP addresses from an event
        /// </summary>
        /// <param name="evt">The event</param>
        /// <returns>A list of IP addresses</returns>
        private List<string> ExtractIPsFromEvent(EventLogEntry evt)
        {
            var ips = new List<string>();
            var ipRegex = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b");

            var matches = ipRegex.Matches(evt.Message);
            foreach (Match match in matches)
            {
                ips.Add(match.Value);
            }

            return ips;
        }

        /// <summary>
        /// Extracts hashes from an event
        /// </summary>
        /// <param name="evt">The event</param>
        /// <returns>A list of hashes</returns>
        private List<string> ExtractHashesFromEvent(EventLogEntry evt)
        {
            var hashes = new List<string>();
            var hashRegex = new Regex(@"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b");

            var matches = hashRegex.Matches(evt.Message);
            foreach (Match match in matches)
            {
                hashes.Add(match.Value);
            }

            return hashes;
        }

        /// <summary>
        /// Extracts CVEs from an event
        /// </summary>
        /// <param name="evt">The event</param>
        /// <returns>A list of CVEs</returns>
        private List<string> ExtractCVEsFromEvent(EventLogEntry evt)
        {
            var cves = new List<string>();
            var cveRegex = new Regex(@"CVE-\d{4}-\d{4,}");

            var matches = cveRegex.Matches(evt.Message);
            foreach (Match match in matches)
            {
                cves.Add(match.Value);
            }

            return cves;
        }

        /// <summary>
        /// Gets a key for grouping events
        /// </summary>
        /// <param name="evt">The event</param>
        /// <param name="groupBy">The property to group by</param>
        /// <returns>The group key</returns>
        private string GetEventGroupKey(EventLogEntry evt, string groupBy)
        {
            switch (groupBy.ToLower())
            {
                case "eventid":
                    return evt.EventId.ToString();
                case "source":
                    return evt.Source;
                case "level":
                    return evt.Level.ToString();
                case "user":
                    return evt.UserName ?? "";
                default:
                    return evt.EventId.ToString();
            }
        }

        /// <summary>
        /// Checks if an event matches a pattern
        /// </summary>
        /// <param name="evt">The event</param>
        /// <param name="pattern">The pattern</param>
        /// <returns>True if the event matches the pattern, false otherwise</returns>
        private bool MatchesPattern(EventLogEntry evt, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return false;
            }

            // Check for special pattern formats
            if (pattern.StartsWith("EventID:"))
            {
                var eventId = pattern.Substring("EventID:".Length).Trim();
                return evt.EventId.ToString() == eventId;
            }
            else if (pattern.StartsWith("Level:"))
            {
                var level = pattern.Substring("Level:".Length).Trim();
                return evt.Level.ToString().Equals(level, StringComparison.OrdinalIgnoreCase);
            }
            else if (pattern.StartsWith("Source:"))
            {
                var source = pattern.Substring("Source:".Length).Trim();
                return evt.Source.Equals(source, StringComparison.OrdinalIgnoreCase);
            }
            else if (pattern.StartsWith("User:"))
            {
                var user = pattern.Substring("User:".Length).Trim();
                return (evt.UserName ?? "").Equals(user, StringComparison.OrdinalIgnoreCase);
            }
            else if (pattern.StartsWith("Regex:"))
            {
                var regex = pattern.Substring("Regex:".Length).Trim();
                try
                {
                    return Regex.IsMatch(evt.Message, regex);
                }
                catch
                {
                    return false;
                }
            }
            else
            {
                // Default to simple string matching in the message
                return evt.Message.Contains(pattern);
            }
        }

        /// <summary>
        /// Triggers a correlation alert
        /// </summary>
        /// <param name="alert">The alert to trigger</param>
        private void TriggerAlert(CorrelationAlert alert)
        {
            _logger.LogWarning($"Correlation alert triggered: {alert.RuleName} - {alert.Description}");
            TotalAlertsTriggered++;
            OnCorrelationAlertTriggered(alert);
        }

        /// <summary>
        /// Cleans up old events from the event buffer
        /// </summary>
        private void CleanupEventBuffer()
        {
            var now = DateTime.Now;
            var cutoffTime = now.AddMinutes(-_eventBufferMaxAge);

            lock (_eventBuffer)
            {
                foreach (var source in _eventBuffer.Keys.ToList())
                {
                    // Remove events older than the cutoff time
                    _eventBuffer[source] = _eventBuffer[source]
                        .Where(e => e.Timestamp >= cutoffTime)
                        .ToList();

                    // Trim the buffer if it's still too large
                    if (_eventBuffer[source].Count > _eventBufferMaxSize)
                    {
                        _eventBuffer[source] = _eventBuffer[source]
                            .OrderByDescending(e => e.Timestamp)
                            .Take(_eventBufferMaxSize)
                            .ToList();
                    }
                }
            }
        }

        /// <summary>
        /// Initializes default correlation rules
        /// </summary>
        private void InitializeDefaultRules()
        {
            try
            {
                // Rule 1: Failed login attempts threshold
                var failedLoginRule = new CorrelationRule
                {
                    Name = "Multiple Failed Logins",
                    Description = "Multiple failed login attempts detected",
                    Type = CorrelationRuleType.ThresholdBased,
                    Severity = AlertSeverity.Medium,
                    IsEnabled = true,
                    RequireAllSources = false,
                    EventSources = new List<string> { "Security" },
                    Parameters = new Dictionary<string, string>
                    {
                        { "threshold", "5" },
                        { "timeWindowSeconds", "300" },
                        { "pattern", "EventID:4625" },
                        { "groupBy", "User" }
                    }
                };
                AddRule(failedLoginRule);

                // Rule 2: Account lockout after failed logins
                var accountLockoutRule = new CorrelationRule
                {
                    Name = "Account Lockout After Failed Logins",
                    Description = "Account lockout following multiple failed login attempts",
                    Type = CorrelationRuleType.SequentialEvents,
                    Severity = AlertSeverity.High,
                    IsEnabled = true,
                    RequireAllSources = false,
                    EventSources = new List<string> { "Security" },
                    Parameters = new Dictionary<string, string>
                    {
                        { "sequence", "EventID:4625|EventID:4625|EventID:4625|EventID:4740" },
                        { "timeWindowSeconds", "300" }
                    }
                };
                AddRule(accountLockoutRule);

                // Rule 3: Malicious IP connection
                var maliciousIPRule = new CorrelationRule
                {
                    Name = "Connection from Malicious IP",
                    Description = "Connection detected from known malicious IP address",
                    Type = CorrelationRuleType.ThreatIntelligence,
                    Severity = AlertSeverity.High,
                    IsEnabled = true,
                    RequireAllSources = false,
                    EventSources = new List<string> { "Security", "System" },
                    Parameters = new Dictionary<string, string>
                    {
                        { "threatType", "ip" },
                        { "timeWindowSeconds", "3600" }
                    }
                };
                AddRule(maliciousIPRule);

                // Rule 4: Malware detection
                var malwareRule = new CorrelationRule
                {
                    Name = "Malware Detection",
                    Description = "Known malware hash detected in events",
                    Type = CorrelationRuleType.ThreatIntelligence,
                    Severity = AlertSeverity.Critical,
                    IsEnabled = true,
                    RequireAllSources = false,
                    EventSources = new List<string> { "Application", "System" },
                    Parameters = new Dictionary<string, string>
                    {
                        { "threatType", "hash" },
                        { "timeWindowSeconds", "3600" }
                    }
                };
                AddRule(malwareRule);

                // Rule 5: Privilege escalation pattern
                var privilegeEscalationRule = new CorrelationRule
                {
                    Name = "Privilege Escalation",
                    Description = "Potential privilege escalation attack detected",
                    Type = CorrelationRuleType.PatternMatching,
                    Severity = AlertSeverity.High,
                    IsEnabled = true,
                    RequireAllSources = false,
                    EventSources = new List<string> { "Security" },
                    Parameters = new Dictionary<string, string>
                    {
                        { "pattern_Security", "EventID:4672" },
                        { "timeWindowSeconds", "300" }
                    }
                };
                AddRule(privilegeEscalationRule);

                _logger.LogInfo("Initialized default correlation rules");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing default rules: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the event log collector's EventLogEntriesCollected event
        /// </summary>
        private void EventLogCollector_EventLogEntriesCollected(object sender, EventLogEntriesCollectedEventArgs e)
        {
            try
            {
                // Add the collected events to the buffer
                lock (_eventBuffer)
                {
                    if (!_eventBuffer.ContainsKey(e.Source))
                    {
                        _eventBuffer[e.Source] = new List<EventLogEntry>();
                    }

                    _eventBuffer[e.Source].AddRange(e.Entries);
                }

                _logger.LogDebug($"Added {e.Entries.Count} events from {e.Source} to the correlation buffer");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error handling collected events: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the event log collector's EventLogCollectionError event
        /// </summary>
        private void EventLogCollector_EventLogCollectionError(object sender, EventLogCollectionErrorEventArgs e)
        {
            _logger.LogWarning($"Event log collection error for source {e.Source}: {e.ErrorMessage}");
        }

        /// <summary>
        /// Handles the correlation timer's Elapsed event
        /// </summary>
        private void CorrelationTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            _correlationTimer.Stop();

            try
            {
                PerformCorrelation();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in correlation timer: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error in event correlation timer");
            }
            finally
            {
                _correlationTimer.Start();
            }
        }

        /// <summary>
        /// Raises the CorrelationAlertTriggered event
        /// </summary>
        /// <param name="alert">The correlation alert</param>
        protected virtual void OnCorrelationAlertTriggered(CorrelationAlert alert)
        {
            CorrelationAlertTriggered?.Invoke(this, new CorrelationAlertEventArgs(alert));
        }

        /// <summary>
        /// Raises the CorrelationError event
        /// </summary>
        /// <param name="ruleName">The name of the rule that had an error</param>
        /// <param name="errorMessage">The error message</param>
        protected virtual void OnCorrelationError(string ruleName, string errorMessage)
        {
            CorrelationError?.Invoke(this, new CorrelationErrorEventArgs(ruleName, errorMessage));
        }
    }

    /// <summary>
    /// Represents a correlation rule
    /// </summary>
    public class CorrelationRule
    {
        /// <summary>
        /// Gets or sets the rule name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the rule description
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the rule type
        /// </summary>
        public CorrelationRuleType Type { get; set; }

        /// <summary>
        /// Gets or sets the rule severity
        /// </summary>
        public AlertSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the rule is enabled
        /// </summary>
        public bool IsEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether all event sources are required
        /// </summary>
        public bool RequireAllSources { get; set; }

        /// <summary>
        /// Gets or sets the event sources
        /// </summary>
        public List<string> EventSources { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the rule parameters
        /// </summary>
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
    }

    /// <summary>
    /// Represents the type of a correlation rule
    /// </summary>
    public enum CorrelationRuleType
    {
        /// <summary>
        /// Rule that looks for a sequence of events
        /// </summary>
        SequentialEvents,

        /// <summary>
        /// Rule that looks for a threshold of similar events
        /// </summary>
        ThresholdBased,

        /// <summary>
        /// Rule that looks for specific patterns across different event sources
        /// </summary>
        PatternMatching,

        /// <summary>
        /// Rule that correlates events with threat intelligence data
        /// </summary>
        ThreatIntelligence
    }

    /// <summary>
    /// Represents a correlation alert
    /// </summary>
    public class CorrelationAlert
    {
        /// <summary>
        /// Gets or sets the rule name
        /// </summary>
        public string RuleName { get; set; }

        /// <summary>
        /// Gets or sets the alert severity
        /// </summary>
        public AlertSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the alert timestamp
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the alert description
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the related events
        /// </summary>
        public List<EventLogEntry> RelatedEvents { get; set; } = new List<EventLogEntry>();
    }

    /// <summary>
    /// Represents the severity of an alert
    /// </summary>
    public enum AlertSeverity
    {
        /// <summary>
        /// Low severity
        /// </summary>
        Low,

        /// <summary>
        /// Medium severity
        /// </summary>
        Medium,

        /// <summary>
        /// High severity
        /// </summary>
        High,

        /// <summary>
        /// Critical severity
        /// </summary>
        Critical
    }

    /// <summary>
    /// Event arguments for the CorrelationAlertTriggered event
    /// </summary>
    public class CorrelationAlertEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the correlation alert
        /// </summary>
        public CorrelationAlert Alert { get; }

        /// <summary>
        /// Initializes a new instance of the CorrelationAlertEventArgs class
        /// </summary>
        /// <param name="alert">The correlation alert</param>
        public CorrelationAlertEventArgs(CorrelationAlert alert)
        {
            Alert = alert;
        }
    }

    /// <summary>
    /// Event arguments for the CorrelationError event
    /// </summary>
    public class CorrelationErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the name of the rule that had an error
        /// </summary>
        public string RuleName { get; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the CorrelationErrorEventArgs class
        /// </summary>
        /// <param name="ruleName">The name of the rule that had an error</param>
        /// <param name="errorMessage">The error message</param>
        public CorrelationErrorEventArgs(string ruleName, string errorMessage)
        {
            RuleName = ruleName;
            ErrorMessage = errorMessage;
        }
    }
}