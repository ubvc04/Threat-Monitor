using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Timers;
using Newtonsoft.Json;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.EventLog
{
    /// <summary>
    /// Manages threat intelligence feeds for bad IPs, malware hashes, and CVEs
    /// </summary>
    public class ThreatIntelligenceManager
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly Timer _updateTimer;
        private readonly HttpClient _httpClient;
        private readonly string _cacheDirectory;

        private HashSet<string> _maliciousIPs = new HashSet<string>();
        private HashSet<string> _malwareHashes = new HashSet<string>();
        private Dictionary<string, CVEInfo> _cveDatabase = new Dictionary<string, CVEInfo>();
        private Dictionary<string, ThreatFeed> _configuredFeeds = new Dictionary<string, ThreatFeed>();

        /// <summary>
        /// Event raised when threat intelligence is updated
        /// </summary>
        public event EventHandler<ThreatIntelligenceUpdatedEventArgs> ThreatIntelligenceUpdated;

        /// <summary>
        /// Event raised when a feed update fails
        /// </summary>
        public event EventHandler<ThreatFeedUpdateErrorEventArgs> ThreatFeedUpdateError;

        /// <summary>
        /// Gets the collection of malicious IPs
        /// </summary>
        public IReadOnlyCollection<string> MaliciousIPs => _maliciousIPs;

        /// <summary>
        /// Gets the collection of malware hashes
        /// </summary>
        public IReadOnlyCollection<string> MalwareHashes => _malwareHashes;

        /// <summary>
        /// Gets the CVE database
        /// </summary>
        public IReadOnlyDictionary<string, CVEInfo> CVEDatabase => _cveDatabase;

        /// <summary>
        /// Gets the configured threat feeds
        /// </summary>
        public IReadOnlyDictionary<string, ThreatFeed> ConfiguredFeeds => _configuredFeeds;

        /// <summary>
        /// Gets or sets the update interval in milliseconds
        /// </summary>
        public int UpdateIntervalMs { get; set; }

        /// <summary>
        /// Gets the last update time
        /// </summary>
        public DateTime LastUpdateTime { get; private set; }

        /// <summary>
        /// Gets a value indicating whether an update is in progress
        /// </summary>
        public bool IsUpdating { get; private set; }

        /// <summary>
        /// Initializes a new instance of the ThreatIntelligenceManager class
        /// </summary>
        /// <param name="updateIntervalMs">Update interval in milliseconds</param>
        /// <param name="cacheDirectory">Directory to cache threat intelligence data</param>
        public ThreatIntelligenceManager(int updateIntervalMs = 3600000, string cacheDirectory = null)
        {
            UpdateIntervalMs = updateIntervalMs;
            _cacheDirectory = cacheDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinSecMonitor", "ThreatIntelligence");

            // Ensure cache directory exists
            Directory.CreateDirectory(_cacheDirectory);

            // Initialize HTTP client
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("WinSecMonitor/1.0");
            _httpClient.Timeout = TimeSpan.FromMinutes(5);

            // Initialize update timer
            _updateTimer = new Timer(UpdateIntervalMs);
            _updateTimer.Elapsed += UpdateTimer_Elapsed;
            _updateTimer.AutoReset = true;

            // Configure default feeds
            ConfigureDefaultFeeds();

            _logger.LogInfo("ThreatIntelligenceManager initialized");
        }

        /// <summary>
        /// Starts the threat intelligence update timer
        /// </summary>
        public void StartUpdates()
        {
            _updateTimer.Start();
            _logger.LogInfo("Threat intelligence updates started");
        }

        /// <summary>
        /// Stops the threat intelligence update timer
        /// </summary>
        public void StopUpdates()
        {
            _updateTimer.Stop();
            _logger.LogInfo("Threat intelligence updates stopped");
        }

        /// <summary>
        /// Updates all threat intelligence feeds
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task UpdateAllFeedsAsync()
        {
            if (IsUpdating)
            {
                return;
            }

            IsUpdating = true;
            var updatedFeeds = new List<string>();
            var failedFeeds = new Dictionary<string, string>();

            try
            {
                _logger.LogInfo("Updating all threat intelligence feeds");

                foreach (var feed in _configuredFeeds.Values)
                {
                    try
                    {
                        var success = await UpdateFeedAsync(feed);
                        if (success)
                        {                            
                            updatedFeeds.Add(feed.Name);
                        }
                        else
                        {
                            failedFeeds.Add(feed.Name, "Feed update returned false");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error updating feed {feed.Name}: {ex.Message}");
                        failedFeeds.Add(feed.Name, ex.Message);
                        OnThreatFeedUpdateError(feed.Name, ex.Message);
                    }
                }

                // Load from cache for any failed feeds
                foreach (var feedName in failedFeeds.Keys)
                {
                    try
                    {
                        LoadFeedFromCache(_configuredFeeds[feedName]);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error loading feed {feedName} from cache: {ex.Message}");
                    }
                }

                LastUpdateTime = DateTime.Now;
                OnThreatIntelligenceUpdated(updatedFeeds, failedFeeds);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating threat intelligence: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error updating threat intelligence");
            }
            finally
            {
                IsUpdating = false;
            }
        }

        /// <summary>
        /// Updates a specific threat feed
        /// </summary>
        /// <param name="feed">The feed to update</param>
        /// <returns>True if the update was successful, false otherwise</returns>
        private async Task<bool> UpdateFeedAsync(ThreatFeed feed)
        {
            try
            {
                _logger.LogInfo($"Updating feed: {feed.Name}");

                string content;
                if (feed.Url.StartsWith("file:"))
                {
                    // Local file feed
                    var filePath = new Uri(feed.Url).LocalPath;
                    if (File.Exists(filePath))
                    {                        
                        content = await File.ReadAllTextAsync(filePath);
                    }
                    else
                    {
                        _logger.LogWarning($"Feed file not found: {filePath}");
                        return false;
                    }
                }
                else
                {
                    // Remote feed
                    var response = await _httpClient.GetAsync(feed.Url);
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogWarning($"Failed to download feed {feed.Name}: {response.StatusCode}");
                        return false;
                    }

                    content = await response.Content.ReadAsStringAsync();
                }

                // Process the feed content based on type
                switch (feed.Type)
                {
                    case ThreatFeedType.MaliciousIP:
                        ProcessMaliciousIPFeed(content, feed.Format);
                        break;
                    case ThreatFeedType.MalwareHash:
                        ProcessMalwareHashFeed(content, feed.Format);
                        break;
                    case ThreatFeedType.CVE:
                        ProcessCVEFeed(content, feed.Format);
                        break;
                    default:
                        _logger.LogWarning($"Unknown feed type: {feed.Type}");
                        return false;
                }

                // Cache the feed content
                await CacheFeedContentAsync(feed, content);

                _logger.LogInfo($"Successfully updated feed: {feed.Name}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating feed {feed.Name}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Processes a malicious IP feed
        /// </summary>
        /// <param name="content">The feed content</param>
        /// <param name="format">The feed format</param>
        private void ProcessMaliciousIPFeed(string content, ThreatFeedFormat format)
        {
            var ips = new HashSet<string>();

            switch (format)
            {
                case ThreatFeedFormat.PlainText:
                    // Process plain text format (one IP per line)
                    using (var reader = new StringReader(content))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                            {
                                // Extract IP address from the line
                                var match = Regex.Match(line, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
                                if (match.Success)
                                {
                                    ips.Add(match.Value);
                                }
                            }
                        }
                    }
                    break;

                case ThreatFeedFormat.CSV:
                    // Process CSV format
                    using (var reader = new StringReader(content))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                            {
                                var parts = line.Split(',');
                                if (parts.Length > 0)
                                {
                                    var ip = parts[0].Trim();
                                    if (Regex.IsMatch(ip, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
                                    {
                                        ips.Add(ip);
                                    }
                                }
                            }
                        }
                    }
                    break;

                case ThreatFeedFormat.JSON:
                    // Process JSON format
                    try
                    {
                        var jsonData = JsonConvert.DeserializeObject<dynamic>(content);
                        if (jsonData is Newtonsoft.Json.Linq.JArray array)
                        {
                            foreach (var item in array)
                            {
                                if (item["ip"] != null)
                                {
                                    var ip = item["ip"].ToString();
                                    if (Regex.IsMatch(ip, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
                                    {
                                        ips.Add(ip);
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error parsing JSON IP feed: {ex.Message}");
                    }
                    break;
            }

            // Update the malicious IPs collection
            lock (_maliciousIPs)
            {
                foreach (var ip in ips)
                {
                    _maliciousIPs.Add(ip);
                }
            }

            _logger.LogInfo($"Processed {ips.Count} malicious IPs");
        }

        /// <summary>
        /// Processes a malware hash feed
        /// </summary>
        /// <param name="content">The feed content</param>
        /// <param name="format">The feed format</param>
        private void ProcessMalwareHashFeed(string content, ThreatFeedFormat format)
        {
            var hashes = new HashSet<string>();

            switch (format)
            {
                case ThreatFeedFormat.PlainText:
                    // Process plain text format (one hash per line)
                    using (var reader = new StringReader(content))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                            {
                                // Extract hash from the line (MD5, SHA1, SHA256)
                                var match = Regex.Match(line, @"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b");
                                if (match.Success)
                                {
                                    hashes.Add(match.Value.ToLower());
                                }
                            }
                        }
                    }
                    break;

                case ThreatFeedFormat.CSV:
                    // Process CSV format
                    using (var reader = new StringReader(content))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                            {
                                var parts = line.Split(',');
                                if (parts.Length > 0)
                                {
                                    var hash = parts[0].Trim();
                                    if (Regex.IsMatch(hash, @"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b"))
                                    {
                                        hashes.Add(hash.ToLower());
                                    }
                                }
                            }
                        }
                    }
                    break;

                case ThreatFeedFormat.JSON:
                    // Process JSON format
                    try
                    {
                        var jsonData = JsonConvert.DeserializeObject<dynamic>(content);
                        if (jsonData is Newtonsoft.Json.Linq.JArray array)
                        {
                            foreach (var item in array)
                            {
                                if (item["hash"] != null)
                                {
                                    var hash = item["hash"].ToString();
                                    if (Regex.IsMatch(hash, @"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b"))
                                    {
                                        hashes.Add(hash.ToLower());
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error parsing JSON hash feed: {ex.Message}");
                    }
                    break;
            }

            // Update the malware hashes collection
            lock (_malwareHashes)
            {
                foreach (var hash in hashes)
                {
                    _malwareHashes.Add(hash);
                }
            }

            _logger.LogInfo($"Processed {hashes.Count} malware hashes");
        }

        /// <summary>
        /// Processes a CVE feed
        /// </summary>
        /// <param name="content">The feed content</param>
        /// <param name="format">The feed format</param>
        private void ProcessCVEFeed(string content, ThreatFeedFormat format)
        {
            var cves = new Dictionary<string, CVEInfo>();

            switch (format)
            {
                case ThreatFeedFormat.JSON:
                    // Process JSON format
                    try
                    {
                        var jsonData = JsonConvert.DeserializeObject<dynamic>(content);
                        if (jsonData is Newtonsoft.Json.Linq.JArray array)
                        {
                            foreach (var item in array)
                            {
                                if (item["id"] != null)
                                {
                                    var id = item["id"].ToString();
                                    if (Regex.IsMatch(id, @"CVE-\d{4}-\d{4,}"))
                                    {
                                        var cve = new CVEInfo
                                        {
                                            Id = id,
                                            Description = item["description"]?.ToString() ?? "",
                                            Severity = ParseCVESeverity(item["severity"]?.ToString() ?? ""),
                                            PublishedDate = ParseCVEDate(item["published"]?.ToString() ?? ""),
                                            LastModifiedDate = ParseCVEDate(item["modified"]?.ToString() ?? ""),
                                            References = ParseCVEReferences(item["references"])
                                        };

                                        cves[id] = cve;
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error parsing JSON CVE feed: {ex.Message}");
                    }
                    break;

                case ThreatFeedFormat.CSV:
                    // Process CSV format
                    using (var reader = new StringReader(content))
                    {
                        string line;
                        bool isHeader = true;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (isHeader)
                            {
                                isHeader = false;
                                continue;
                            }

                            line = line.Trim();
                            if (!string.IsNullOrWhiteSpace(line))
                            {
                                var parts = line.Split(',');
                                if (parts.Length >= 4)
                                {
                                    var id = parts[0].Trim();
                                    if (Regex.IsMatch(id, @"CVE-\d{4}-\d{4,}"))
                                    {
                                        var cve = new CVEInfo
                                        {
                                            Id = id,
                                            Description = parts[1].Trim(),
                                            Severity = ParseCVESeverity(parts[2].Trim()),
                                            PublishedDate = ParseCVEDate(parts[3].Trim())
                                        };

                                        cves[id] = cve;
                                    }
                                }
                            }
                        }
                    }
                    break;
            }

            // Update the CVE database
            lock (_cveDatabase)
            {
                foreach (var kvp in cves)
                {
                    _cveDatabase[kvp.Key] = kvp.Value;
                }
            }

            _logger.LogInfo($"Processed {cves.Count} CVEs");
        }

        /// <summary>
        /// Parses CVE severity from a string
        /// </summary>
        /// <param name="severity">The severity string</param>
        /// <returns>The parsed CVE severity</returns>
        private CVESeverity ParseCVESeverity(string severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
            {
                return CVESeverity.Unknown;
            }

            severity = severity.ToLower();

            if (severity.Contains("critical"))
            {
                return CVESeverity.Critical;
            }
            else if (severity.Contains("high"))
            {
                return CVESeverity.High;
            }
            else if (severity.Contains("medium") || severity.Contains("moderate"))
            {
                return CVESeverity.Medium;
            }
            else if (severity.Contains("low"))
            {
                return CVESeverity.Low;
            }
            else
            {
                return CVESeverity.Unknown;
            }
        }

        /// <summary>
        /// Parses a CVE date from a string
        /// </summary>
        /// <param name="dateString">The date string</param>
        /// <returns>The parsed date</returns>
        private DateTime ParseCVEDate(string dateString)
        {
            if (DateTime.TryParse(dateString, out var date))
            {
                return date;
            }

            return DateTime.MinValue;
        }

        /// <summary>
        /// Parses CVE references from a JSON token
        /// </summary>
        /// <param name="referencesToken">The references token</param>
        /// <returns>A list of references</returns>
        private List<string> ParseCVEReferences(dynamic referencesToken)
        {
            var references = new List<string>();

            try
            {
                if (referencesToken != null && referencesToken is Newtonsoft.Json.Linq.JArray array)
                {
                    foreach (var reference in array)
                    {
                        if (reference is string str)
                        {
                            references.Add(str);
                        }
                        else if (reference["url"] != null)
                        {
                            references.Add(reference["url"].ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error parsing CVE references: {ex.Message}");
            }

            return references;
        }

        /// <summary>
        /// Caches feed content to a file
        /// </summary>
        /// <param name="feed">The feed</param>
        /// <param name="content">The feed content</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task CacheFeedContentAsync(ThreatFeed feed, string content)
        {
            try
            {
                var cacheFilePath = GetCacheFilePath(feed);
                await File.WriteAllTextAsync(cacheFilePath, content);
                _logger.LogInfo($"Cached feed content for {feed.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to cache feed content for {feed.Name}: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads a feed from cache
        /// </summary>
        /// <param name="feed">The feed to load</param>
        private void LoadFeedFromCache(ThreatFeed feed)
        {
            try
            {
                var cacheFilePath = GetCacheFilePath(feed);
                if (File.Exists(cacheFilePath))
                {
                    var content = File.ReadAllText(cacheFilePath);
                    _logger.LogInfo($"Loading feed {feed.Name} from cache");

                    // Process the feed content based on type
                    switch (feed.Type)
                    {
                        case ThreatFeedType.MaliciousIP:
                            ProcessMaliciousIPFeed(content, feed.Format);
                            break;
                        case ThreatFeedType.MalwareHash:
                            ProcessMalwareHashFeed(content, feed.Format);
                            break;
                        case ThreatFeedType.CVE:
                            ProcessCVEFeed(content, feed.Format);
                            break;
                    }
                }
                else
                {
                    _logger.LogWarning($"No cache file found for feed {feed.Name}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error loading feed {feed.Name} from cache: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the cache file path for a feed
        /// </summary>
        /// <param name="feed">The feed</param>
        /// <returns>The cache file path</returns>
        private string GetCacheFilePath(ThreatFeed feed)
        {
            // Create a hash of the feed URL to use as the filename
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(feed.Url));
                var hashString = BitConverter.ToString(hash).Replace("-", "").ToLower();
                return Path.Combine(_cacheDirectory, $"{feed.Name}_{hashString}.cache");
            }
        }

        /// <summary>
        /// Adds a custom threat feed
        /// </summary>
        /// <param name="name">The feed name</param>
        /// <param name="url">The feed URL</param>
        /// <param name="type">The feed type</param>
        /// <param name="format">The feed format</param>
        public void AddFeed(string name, string url, ThreatFeedType type, ThreatFeedFormat format)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(url))
            {
                throw new ArgumentException("Feed name and URL cannot be empty");
            }

            if (_configuredFeeds.ContainsKey(name))
            {
                throw new ArgumentException($"Feed with name '{name}' already exists");
            }

            var feed = new ThreatFeed
            {
                Name = name,
                Url = url,
                Type = type,
                Format = format
            };

            _configuredFeeds[name] = feed;
            _logger.LogInfo($"Added feed: {name}, Type: {type}, Format: {format}");
        }

        /// <summary>
        /// Removes a threat feed
        /// </summary>
        /// <param name="name">The feed name</param>
        public void RemoveFeed(string name)
        {
            if (_configuredFeeds.ContainsKey(name))
            {
                _configuredFeeds.Remove(name);
                _logger.LogInfo($"Removed feed: {name}");
            }
        }

        /// <summary>
        /// Checks if an IP address is in the malicious IP list
        /// </summary>
        /// <param name="ip">The IP address to check</param>
        /// <returns>True if the IP is malicious, false otherwise</returns>
        public bool IsMaliciousIP(string ip)
        {
            return _maliciousIPs.Contains(ip);
        }

        /// <summary>
        /// Checks if a file hash is in the malware hash list
        /// </summary>
        /// <param name="hash">The hash to check</param>
        /// <returns>True if the hash is associated with malware, false otherwise</returns>
        public bool IsMalwareHash(string hash)
        {
            return _malwareHashes.Contains(hash.ToLower());
        }

        /// <summary>
        /// Gets information about a CVE
        /// </summary>
        /// <param name="cveId">The CVE ID</param>
        /// <returns>The CVE information, or null if not found</returns>
        public CVEInfo GetCVEInfo(string cveId)
        {
            if (_cveDatabase.TryGetValue(cveId, out var cveInfo))
            {
                return cveInfo;
            }

            return null;
        }

        /// <summary>
        /// Configures default threat feeds
        /// </summary>
        private void ConfigureDefaultFeeds()
        {
            try
            {
                // Example feeds - in a real application, these would be actual threat intelligence feeds
                // Note: These are placeholder URLs and would need to be replaced with actual feeds

                // Malicious IP feeds
                AddFeed("EmergingThreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 
                    ThreatFeedType.MaliciousIP, ThreatFeedFormat.PlainText);

                // Malware hash feeds
                AddFeed("MalwareHashes", "https://virusshare.com/hashes.txt", 
                    ThreatFeedType.MalwareHash, ThreatFeedFormat.PlainText);

                // CVE feeds
                AddFeed("NVD", "https://services.nvd.nist.gov/rest/json/cves/1.0", 
                    ThreatFeedType.CVE, ThreatFeedFormat.JSON);

                _logger.LogInfo("Configured default threat feeds");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error configuring default feeds: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the update timer elapsed event
        /// </summary>
        private async void UpdateTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            _updateTimer.Stop();

            try
            {
                await UpdateAllFeedsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in update timer: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error in threat intelligence update timer");
            }
            finally
            {
                _updateTimer.Start();
            }
        }

        /// <summary>
        /// Raises the ThreatIntelligenceUpdated event
        /// </summary>
        /// <param name="updatedFeeds">The list of updated feeds</param>
        /// <param name="failedFeeds">The dictionary of failed feeds and error messages</param>
        protected virtual void OnThreatIntelligenceUpdated(List<string> updatedFeeds, Dictionary<string, string> failedFeeds)
        {
            ThreatIntelligenceUpdated?.Invoke(this, new ThreatIntelligenceUpdatedEventArgs(updatedFeeds, failedFeeds));
        }

        /// <summary>
        /// Raises the ThreatFeedUpdateError event
        /// </summary>
        /// <param name="feedName">The name of the feed that had an error</param>
        /// <param name="errorMessage">The error message</param>
        protected virtual void OnThreatFeedUpdateError(string feedName, string errorMessage)
        {
            ThreatFeedUpdateError?.Invoke(this, new ThreatFeedUpdateErrorEventArgs(feedName, errorMessage));
        }
    }

    /// <summary>
    /// Represents a threat intelligence feed
    /// </summary>
    public class ThreatFeed
    {
        /// <summary>
        /// Gets or sets the feed name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the feed URL
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// Gets or sets the feed type
        /// </summary>
        public ThreatFeedType Type { get; set; }

        /// <summary>
        /// Gets or sets the feed format
        /// </summary>
        public ThreatFeedFormat Format { get; set; }
    }

    /// <summary>
    /// Represents the type of a threat feed
    /// </summary>
    public enum ThreatFeedType
    {
        /// <summary>
        /// Malicious IP addresses
        /// </summary>
        MaliciousIP,

        /// <summary>
        /// Malware hashes
        /// </summary>
        MalwareHash,

        /// <summary>
        /// Common Vulnerabilities and Exposures
        /// </summary>
        CVE
    }

    /// <summary>
    /// Represents the format of a threat feed
    /// </summary>
    public enum ThreatFeedFormat
    {
        /// <summary>
        /// Plain text format
        /// </summary>
        PlainText,

        /// <summary>
        /// CSV format
        /// </summary>
        CSV,

        /// <summary>
        /// JSON format
        /// </summary>
        JSON
    }

    /// <summary>
    /// Represents information about a CVE
    /// </summary>
    public class CVEInfo
    {
        /// <summary>
        /// Gets or sets the CVE ID
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the CVE description
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the CVE severity
        /// </summary>
        public CVESeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the CVE published date
        /// </summary>
        public DateTime PublishedDate { get; set; }

        /// <summary>
        /// Gets or sets the CVE last modified date
        /// </summary>
        public DateTime LastModifiedDate { get; set; }

        /// <summary>
        /// Gets or sets the CVE references
        /// </summary>
        public List<string> References { get; set; } = new List<string>();
    }

    /// <summary>
    /// Represents the severity of a CVE
    /// </summary>
    public enum CVESeverity
    {
        /// <summary>
        /// Critical severity
        /// </summary>
        Critical,

        /// <summary>
        /// High severity
        /// </summary>
        High,

        /// <summary>
        /// Medium severity
        /// </summary>
        Medium,

        /// <summary>
        /// Low severity
        /// </summary>
        Low,

        /// <summary>
        /// Unknown severity
        /// </summary>
        Unknown
    }

    /// <summary>
    /// Event arguments for the ThreatIntelligenceUpdated event
    /// </summary>
    public class ThreatIntelligenceUpdatedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the list of updated feeds
        /// </summary>
        public List<string> UpdatedFeeds { get; }

        /// <summary>
        /// Gets the dictionary of failed feeds and error messages
        /// </summary>
        public Dictionary<string, string> FailedFeeds { get; }

        /// <summary>
        /// Initializes a new instance of the ThreatIntelligenceUpdatedEventArgs class
        /// </summary>
        /// <param name="updatedFeeds">The list of updated feeds</param>
        /// <param name="failedFeeds">The dictionary of failed feeds and error messages</param>
        public ThreatIntelligenceUpdatedEventArgs(List<string> updatedFeeds, Dictionary<string, string> failedFeeds)
        {
            UpdatedFeeds = updatedFeeds;
            FailedFeeds = failedFeeds;
        }
    }

    /// <summary>
    /// Event arguments for the ThreatFeedUpdateError event
    /// </summary>
    public class ThreatFeedUpdateErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the name of the feed that had an error
        /// </summary>
        public string FeedName { get; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the ThreatFeedUpdateErrorEventArgs class
        /// </summary>
        /// <param name="feedName">The name of the feed that had an error</param>
        /// <param name="errorMessage">The error message</param>
        public ThreatFeedUpdateErrorEventArgs(string feedName, string errorMessage)
        {
            FeedName = feedName;
            ErrorMessage = errorMessage;
        }
    }
}