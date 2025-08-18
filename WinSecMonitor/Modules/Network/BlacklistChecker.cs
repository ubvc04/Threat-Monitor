using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Network
{
    /// <summary>
    /// Checks IP addresses against blacklists and detects suspicious IPs
    /// </summary>
    public class BlacklistChecker
    {
        #region Private Fields

        private readonly HashSet<string> _blacklistedIps;
        private readonly HashSet<string> _whitelistedIps;
        private readonly HashSet<string> _knownMaliciousDomains;
        private readonly Dictionary<string, DateTime> _checkedIps;
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromHours(24);
        private readonly HttpClient _httpClient;

        // Common private IP ranges that should not be flagged
        private readonly List<IPNetwork> _privateNetworks;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the BlacklistChecker class
        /// </summary>
        public BlacklistChecker()
        {
            _blacklistedIps = new HashSet<string>();
            _whitelistedIps = new HashSet<string>();
            _knownMaliciousDomains = new HashSet<string>();
            _checkedIps = new Dictionary<string, DateTime>();
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(5); // Short timeout to avoid slowing down the system

            // Initialize private networks
            _privateNetworks = new List<IPNetwork>
            {
                new IPNetwork("10.0.0.0", "10.255.255.255"),     // 10.0.0.0/8
                new IPNetwork("172.16.0.0", "172.31.255.255"),   // 172.16.0.0/12
                new IPNetwork("192.168.0.0", "192.168.255.255"), // 192.168.0.0/16
                new IPNetwork("127.0.0.0", "127.255.255.255"),   // 127.0.0.0/8 (localhost)
                new IPNetwork("169.254.0.0", "169.254.255.255")  // 169.254.0.0/16 (link-local)
            };

            // Initialize with some known malicious domains
            InitializeKnownMaliciousDomains();

            LogInfo("BlacklistChecker initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Checks if an IP address is blacklisted
        /// </summary>
        public async Task<BlacklistCheckResult> CheckIpAsync(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress) || ipAddress == "*")
            {
                return new BlacklistCheckResult { IsBlacklisted = false, Reason = "Invalid IP address" };
            }

            try
            {
                // Check if the IP is in the whitelist
                if (_whitelistedIps.Contains(ipAddress))
                {
                    return new BlacklistCheckResult { IsBlacklisted = false, Reason = "Whitelisted IP" };
                }

                // Check if the IP is in the blacklist
                if (_blacklistedIps.Contains(ipAddress))
                {
                    return new BlacklistCheckResult { IsBlacklisted = true, Reason = "Blacklisted IP" };
                }

                // Check if the IP is a private IP
                if (IsPrivateIp(ipAddress))
                {
                    return new BlacklistCheckResult { IsBlacklisted = false, Reason = "Private IP" };
                }

                // Check if we've already checked this IP recently
                if (_checkedIps.TryGetValue(ipAddress, out DateTime lastChecked))
                {
                    if (DateTime.Now - lastChecked < _cacheExpiration)
                    {
                        // Use the cached result
                        return new BlacklistCheckResult { IsBlacklisted = false, Reason = "Recently checked" };
                    }
                }

                // Check if the IP is suspicious based on patterns
                if (IsSuspiciousIpPattern(ipAddress))
                {
                    return new BlacklistCheckResult { IsBlacklisted = true, Reason = "Suspicious IP pattern" };
                }

                // Check if the IP is associated with a known malicious domain
                if (await IsAssociatedWithMaliciousDomainAsync(ipAddress))
                {
                    return new BlacklistCheckResult { IsBlacklisted = true, Reason = "Associated with malicious domain" };
                }

                // Update the cache
                _checkedIps[ipAddress] = DateTime.Now;

                return new BlacklistCheckResult { IsBlacklisted = false, Reason = "Not blacklisted" };
            }
            catch (Exception ex)
            {
                LogError($"Error checking IP {ipAddress}: {ex.Message}");
                return new BlacklistCheckResult { IsBlacklisted = false, Reason = $"Error: {ex.Message}" };
            }
        }

        /// <summary>
        /// Adds an IP address to the blacklist
        /// </summary>
        public void AddToBlacklist(string ipAddress)
        {
            if (!string.IsNullOrEmpty(ipAddress) && !_blacklistedIps.Contains(ipAddress))
            {
                _blacklistedIps.Add(ipAddress);
                LogInfo($"Added {ipAddress} to blacklist");
            }
        }

        /// <summary>
        /// Removes an IP address from the blacklist
        /// </summary>
        public void RemoveFromBlacklist(string ipAddress)
        {
            if (!string.IsNullOrEmpty(ipAddress) && _blacklistedIps.Contains(ipAddress))
            {
                _blacklistedIps.Remove(ipAddress);
                LogInfo($"Removed {ipAddress} from blacklist");
            }
        }

        /// <summary>
        /// Adds an IP address to the whitelist
        /// </summary>
        public void AddToWhitelist(string ipAddress)
        {
            if (!string.IsNullOrEmpty(ipAddress) && !_whitelistedIps.Contains(ipAddress))
            {
                _whitelistedIps.Add(ipAddress);
                LogInfo($"Added {ipAddress} to whitelist");
            }
        }

        /// <summary>
        /// Removes an IP address from the whitelist
        /// </summary>
        public void RemoveFromWhitelist(string ipAddress)
        {
            if (!string.IsNullOrEmpty(ipAddress) && _whitelistedIps.Contains(ipAddress))
            {
                _whitelistedIps.Remove(ipAddress);
                LogInfo($"Removed {ipAddress} from whitelist");
            }
        }

        /// <summary>
        /// Loads blacklisted IPs from a file
        /// </summary>
        public void LoadBlacklistFromFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string[] lines = File.ReadAllLines(filePath);
                    foreach (string line in lines)
                    {
                        string ip = line.Trim();
                        if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("#"))
                        {
                            AddToBlacklist(ip);
                        }
                    }

                    LogInfo($"Loaded {lines.Length} IPs from blacklist file");
                }
                else
                {
                    LogError($"Blacklist file not found: {filePath}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error loading blacklist from file: {ex.Message}");
            }
        }

        /// <summary>
        /// Saves blacklisted IPs to a file
        /// </summary>
        public void SaveBlacklistToFile(string filePath)
        {
            try
            {
                File.WriteAllLines(filePath, _blacklistedIps);
                LogInfo($"Saved {_blacklistedIps.Count} IPs to blacklist file");
            }
            catch (Exception ex)
            {
                LogError($"Error saving blacklist to file: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads whitelisted IPs from a file
        /// </summary>
        public void LoadWhitelistFromFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string[] lines = File.ReadAllLines(filePath);
                    foreach (string line in lines)
                    {
                        string ip = line.Trim();
                        if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("#"))
                        {
                            AddToWhitelist(ip);
                        }
                    }

                    LogInfo($"Loaded {lines.Length} IPs from whitelist file");
                }
                else
                {
                    LogError($"Whitelist file not found: {filePath}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error loading whitelist from file: {ex.Message}");
            }
        }

        /// <summary>
        /// Saves whitelisted IPs to a file
        /// </summary>
        public void SaveWhitelistToFile(string filePath)
        {
            try
            {
                File.WriteAllLines(filePath, _whitelistedIps);
                LogInfo($"Saved {_whitelistedIps.Count} IPs to whitelist file");
            }
            catch (Exception ex)
            {
                LogError($"Error saving whitelist to file: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds a known malicious domain
        /// </summary>
        public void AddMaliciousDomain(string domain)
        {
            if (!string.IsNullOrEmpty(domain) && !_knownMaliciousDomains.Contains(domain))
            {
                _knownMaliciousDomains.Add(domain);
                LogInfo($"Added {domain} to malicious domains list");
            }
        }

        /// <summary>
        /// Loads known malicious domains from a file
        /// </summary>
        public void LoadMaliciousDomainsFromFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string[] lines = File.ReadAllLines(filePath);
                    foreach (string line in lines)
                    {
                        string domain = line.Trim();
                        if (!string.IsNullOrEmpty(domain) && !domain.StartsWith("#"))
                        {
                            AddMaliciousDomain(domain);
                        }
                    }

                    LogInfo($"Loaded {lines.Length} domains from malicious domains file");
                }
                else
                {
                    LogError($"Malicious domains file not found: {filePath}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error loading malicious domains from file: {ex.Message}");
            }
        }

        /// <summary>
        /// Saves known malicious domains to a file
        /// </summary>
        public void SaveMaliciousDomainsToFile(string filePath)
        {
            try
            {
                File.WriteAllLines(filePath, _knownMaliciousDomains);
                LogInfo($"Saved {_knownMaliciousDomains.Count} domains to malicious domains file");
            }
            catch (Exception ex)
            {
                LogError($"Error saving malicious domains to file: {ex.Message}");
            }
        }

        /// <summary>
        /// Clears the cache of checked IPs
        /// </summary>
        public void ClearCache()
        {
            _checkedIps.Clear();
            LogInfo("Cleared IP check cache");
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the list of known malicious domains
        /// </summary>
        private void InitializeKnownMaliciousDomains()
        {
            // This is a placeholder for a real implementation
            // In a real implementation, this would load from a file or database
            string[] maliciousDomains = new string[]
            {
                "malware.com",
                "phishing.example.com",
                "badsite.net",
                "malicious.org",
                "trojan.example.net"
            };

            foreach (string domain in maliciousDomains)
            {
                _knownMaliciousDomains.Add(domain);
            }
        }

        /// <summary>
        /// Checks if an IP address is a private IP
        /// </summary>
        private bool IsPrivateIp(string ipAddress)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipAddress);
                byte[] bytes = ip.GetAddressBytes();

                // Check if the IP is in any of the private networks
                foreach (var network in _privateNetworks)
                {
                    if (network.Contains(ip))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if an IP address has a suspicious pattern
        /// </summary>
        private bool IsSuspiciousIpPattern(string ipAddress)
        {
            try
            {
                // Check for suspicious patterns in the IP address
                // This is a placeholder for more sophisticated detection logic
                // In a real implementation, this would check for known patterns used by malware

                // Example: Check for sequential octets which might indicate scanning
                string[] octets = ipAddress.Split('.');
                if (octets.Length == 4)
                {
                    if (octets[0] == octets[1] && octets[1] == octets[2] && octets[2] == octets[3])
                    {
                        return true; // All octets are the same (e.g., 1.1.1.1)
                    }

                    if (int.TryParse(octets[0], out int first) &&
                        int.TryParse(octets[1], out int second) &&
                        int.TryParse(octets[2], out int third) &&
                        int.TryParse(octets[3], out int fourth))
                    {
                        if (second == first + 1 && third == second + 1 && fourth == third + 1)
                        {
                            return true; // Sequential octets (e.g., 1.2.3.4)
                        }
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if an IP address is associated with a known malicious domain
        /// </summary>
        private async Task<bool> IsAssociatedWithMaliciousDomainAsync(string ipAddress)
        {
            try
            {
                // This is a placeholder for a real implementation
                // In a real implementation, this would check DNS records or use a threat intelligence API

                // For now, we'll just return false to avoid slowing down the system
                return false;
            }
            catch (Exception ex)
            {
                LogError($"Error checking if IP is associated with malicious domain: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [BlacklistChecker] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [BlacklistChecker] {message}");
        }

        #endregion
    }

    /// <summary>
    /// Represents the result of a blacklist check
    /// </summary>
    public class BlacklistCheckResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether the IP is blacklisted
        /// </summary>
        public bool IsBlacklisted { get; set; }

        /// <summary>
        /// Gets or sets the reason for the blacklist check result
        /// </summary>
        public string Reason { get; set; }
    }

    /// <summary>
    /// Represents an IP network range
    /// </summary>
    public class IPNetwork
    {
        private readonly IPAddress _startAddress;
        private readonly IPAddress _endAddress;

        /// <summary>
        /// Initializes a new instance of the IPNetwork class
        /// </summary>
        public IPNetwork(string startAddress, string endAddress)
        {
            _startAddress = IPAddress.Parse(startAddress);
            _endAddress = IPAddress.Parse(endAddress);
        }

        /// <summary>
        /// Checks if an IP address is contained in this network
        /// </summary>
        public bool Contains(IPAddress address)
        {
            byte[] addressBytes = address.GetAddressBytes();
            byte[] startBytes = _startAddress.GetAddressBytes();
            byte[] endBytes = _endAddress.GetAddressBytes();

            bool lowerBoundary = true;
            bool upperBoundary = true;

            for (int i = 0; i < addressBytes.Length && (lowerBoundary || upperBoundary); i++)
            {
                if ((lowerBoundary && addressBytes[i] < startBytes[i]) ||
                    (upperBoundary && addressBytes[i] > endBytes[i]))
                {
                    return false;
                }

                lowerBoundary &= (addressBytes[i] == startBytes[i]);
                upperBoundary &= (addressBytes[i] == endBytes[i]);
            }

            return true;
        }
    }
}