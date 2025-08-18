using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace WinSecMonitor.Modules.Processes
{
    /// <summary>
    /// Analyzes PowerShell commands to detect potentially malicious encoded commands
    /// </summary>
    public class PowerShellCommandAnalyzer
    {
        #region Private Fields

        private readonly HashSet<string> _suspiciousTerms;
        private readonly Regex _encodedCommandRegex;
        private readonly Regex _base64Regex;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the PowerShellCommandAnalyzer class
        /// </summary>
        public PowerShellCommandAnalyzer()
        {
            // Initialize regex patterns for detecting encoded commands
            _encodedCommandRegex = new Regex(@"(?:powershell|pwsh)(?:.exe)?\s+(?:.+\s+)?(?:-[eE]\s+|-[eE][nN][cC]\s+|-[eE][nN][cC][oO][dD][eE][dD]\s+|-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]\s+)([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            
            // Regex for validating Base64 strings
            _base64Regex = new Regex(@"^[A-Za-z0-9+/=]+$", RegexOptions.Compiled);
            
            // Initialize list of suspicious terms to look for in decoded commands
            _suspiciousTerms = InitializeSuspiciousTerms();
            
            LogInfo("PowerShellCommandAnalyzer initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Analyzes a command line to detect encoded PowerShell commands
        /// </summary>
        /// <param name="commandLine">The command line to analyze</param>
        /// <returns>Analysis result with details about the command</returns>
        public PowerShellAnalysisResult AnalyzeCommand(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
            {
                return new PowerShellAnalysisResult
                {
                    IsEncodedCommand = false,
                    IsSuspicious = false,
                    CommandLine = commandLine
                };
            }

            // Check if this is a PowerShell command with encoding
            var match = _encodedCommandRegex.Match(commandLine);
            if (!match.Success || match.Groups.Count < 2)
            {
                return new PowerShellAnalysisResult
                {
                    IsEncodedCommand = false,
                    IsSuspicious = false,
                    CommandLine = commandLine
                };
            }

            // Extract the encoded content
            string encodedContent = match.Groups[1].Value;
            if (string.IsNullOrEmpty(encodedContent) || !IsValidBase64(encodedContent))
            {
                return new PowerShellAnalysisResult
                {
                    IsEncodedCommand = true,
                    IsSuspicious = true, // Consider invalid Base64 as suspicious
                    CommandLine = commandLine,
                    EncodedContent = encodedContent,
                    DecodedContent = "[Invalid Base64 content]",
                    SuspiciousReason = "Invalid Base64 encoding"
                };
            }

            // Decode the content
            string decodedContent = DecodeBase64(encodedContent);
            
            // Check for suspicious content
            bool isSuspicious = false;
            string suspiciousReason = string.Empty;
            
            foreach (var term in _suspiciousTerms)
            {
                if (decodedContent.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    isSuspicious = true;
                    suspiciousReason = $"Contains suspicious term: {term}";
                    break;
                }
            }

            // Check for additional suspicious patterns
            if (!isSuspicious)
            {
                if (ContainsObfuscationPatterns(decodedContent))
                {
                    isSuspicious = true;
                    suspiciousReason = "Contains obfuscation patterns";
                }
                else if (ContainsDownloadExecutePatterns(decodedContent))
                {
                    isSuspicious = true;
                    suspiciousReason = "Contains download and execute patterns";
                }
                else if (ContainsSystemModificationPatterns(decodedContent))
                {
                    isSuspicious = true;
                    suspiciousReason = "Contains system modification patterns";
                }
            }

            return new PowerShellAnalysisResult
            {
                IsEncodedCommand = true,
                IsSuspicious = isSuspicious,
                CommandLine = commandLine,
                EncodedContent = encodedContent,
                DecodedContent = decodedContent,
                SuspiciousReason = suspiciousReason
            };
        }

        /// <summary>
        /// Checks if a string is a valid Base64 encoded string
        /// </summary>
        /// <param name="input">The string to check</param>
        /// <returns>True if the string is valid Base64, false otherwise</returns>
        public bool IsValidBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return false;
            }

            // Check if the string matches the Base64 pattern
            if (!_base64Regex.IsMatch(input))
            {
                return false;
            }

            // Check if the length is valid for Base64
            if (input.Length % 4 != 0)
            {
                return false;
            }

            // Try to decode it
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Decodes a Base64 encoded string
        /// </summary>
        /// <param name="encodedString">The Base64 encoded string</param>
        /// <returns>The decoded string</returns>
        public string DecodeBase64(string encodedString)
        {
            try
            {
                byte[] data = Convert.FromBase64String(encodedString);
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                return "[Decoding error]";
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the set of suspicious terms to look for in decoded commands
        /// </summary>
        private HashSet<string> InitializeSuspiciousTerms()
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Command execution
                "invoke-expression", "iex", "invoke-command", "icm",
                
                // Web requests
                "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
                "net.webclient", "downloadstring", "downloadfile",
                "start-bitstransfer", "system.net.sockets",
                
                // Execution policy bypass
                "bypass", "unrestricted", "executionpolicy",
                
                // Code injection
                "reflection.assembly", "loadwithpartialname", "gettype",
                "createinstance", "addscript", "addcommand",
                
                // Shellcode
                "virtualalloc", "memorystream", "runtimeinvoker", "shellcode",
                
                // Obfuscation
                "join", "replace", "reverse", "substring", "base64",
                
                // System modification
                "registry", "hklm:", "hkcu:", "new-service", "set-service",
                "get-wmiobject", "get-ciminstance", "win32_process",
                
                // Credential access
                "get-credential", "convertto-securestring", "net user",
                "mimikatz", "sekurlsa", "lsadump", "hashdump",
                
                // Persistence
                "new-object -com", "wscript.shell", "scheduledtask",
                "startup", "runkey", "autorun", "logonscript"
            };
        }

        /// <summary>
        /// Checks if the decoded content contains obfuscation patterns
        /// </summary>
        private bool ContainsObfuscationPatterns(string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return false;
            }

            // Check for character replacement/joining techniques
            var obfuscationPatterns = new[]
            {
                @"\[char\]\d+", // [char]101
                @"\[string\]\[char\]", // [string][char]
                @"\-join\s*\(?", // -join
                @"\-replace", // -replace
                @"\-f\s*@\(", // -f @(
                @"\{\d+\}\s*-f", // {0} -f
                @"\[array\]::reverse", // [array]::reverse
                @"\$\w+\[\d+\]", // $var[0]
                @"\$\w+\s*=\s*\$\w+\s*-replace", // $var = $var -replace
                @"\$\w+\[\d+\.\.\d+\]", // $var[0..5]
                @"\$\(\s*\$\w+\s*\[\d+\]\s*\+\s*\$\w+\s*\[\d+\]\s*\)" // $($var[0] + $var[1])
            };

            return obfuscationPatterns.Any(pattern => Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        /// <summary>
        /// Checks if the decoded content contains download and execute patterns
        /// </summary>
        private bool ContainsDownloadExecutePatterns(string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return false;
            }

            // Check for download and execute patterns
            var downloadExecutePatterns = new[]
            {
                @"(new-object|net\.webclient)\.downloadstring\(\s*['\"]https?://", // Download string from URL
                @"(new-object|net\.webclient)\.downloadfile\(\s*['\"]https?://", // Download file from URL
                @"invoke-webrequest\s+['\"]https?://", // Invoke-WebRequest URL
                @"invoke-restmethod\s+['\"]https?://", // Invoke-RestMethod URL
                @"start-bitstransfer\s+['\"]https?://", // Start-BitsTransfer URL
                @"iex\s*\(\s*new-object\s+net\.webclient\s*\)\.downloadstring", // IEX (New-Object Net.WebClient).DownloadString
                @"iwr\s+['\"]https?://.*['\"]\s*\|\s*iex", // IWR URL | IEX
                @"\&\s*\(\s*\[scriptblock\]::create\s*\(\s*\(.*\)\s*\)\s*\)" // & ([scriptblock]::create((...)))
            };

            return downloadExecutePatterns.Any(pattern => Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        /// <summary>
        /// Checks if the decoded content contains system modification patterns
        /// </summary>
        private bool ContainsSystemModificationPatterns(string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return false;
            }

            // Check for system modification patterns
            var systemModificationPatterns = new[]
            {
                @"new-service", // Create new service
                @"set-(itemproperty|item)\s+['\"]?(hklm|hkcu):\\", // Registry modification
                @"remove-(itemproperty|item)\s+['\"]?(hklm|hkcu):\\", // Registry deletion
                @"new-item\s+['\"]?(hklm|hkcu):\\", // Registry creation
                @"schtasks", // Scheduled tasks
                @"wmic\s+\w+\s+(call|create|delete)", // WMIC operations
                @"net\s+user\s+\w+\s+\w+\s+/add", // Add user
                @"net\s+localgroup\s+administrators\s+\w+\s+/add", // Add to admin group
                @"add-mppreference\s+-exclusion", // Add Windows Defender exclusion
                @"set-mppreference\s+-disable", // Disable Windows Defender
                @"stop-service\s+windefend", // Stop Windows Defender service
                @"icacls\s+.*\s+/grant\s+everyone", // Change file permissions
                @"attrib\s+.*\s+\+h", // Hide files
                @"vssadmin\s+delete\s+shadows" // Delete shadow copies
            };

            return systemModificationPatterns.Any(pattern => Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [PowerShellCommandAnalyzer] {message}");
        }

        #endregion
    }

    /// <summary>
    /// Represents the result of analyzing a PowerShell command
    /// </summary>
    public class PowerShellAnalysisResult
    {
        /// <summary>
        /// Gets or sets whether the command is an encoded PowerShell command
        /// </summary>
        public bool IsEncodedCommand { get; set; }

        /// <summary>
        /// Gets or sets whether the command is suspicious
        /// </summary>
        public bool IsSuspicious { get; set; }

        /// <summary>
        /// Gets or sets the original command line
        /// </summary>
        public string CommandLine { get; set; }

        /// <summary>
        /// Gets or sets the encoded content (if any)
        /// </summary>
        public string EncodedContent { get; set; }

        /// <summary>
        /// Gets or sets the decoded content (if any)
        /// </summary>
        public string DecodedContent { get; set; }

        /// <summary>
        /// Gets or sets the reason why the command is suspicious (if any)
        /// </summary>
        public string SuspiciousReason { get; set; }
    }
}