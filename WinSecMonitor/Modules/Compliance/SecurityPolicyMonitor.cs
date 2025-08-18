using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Xml;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Compliance
{
    /// <summary>
    /// Monitors Windows security policies including firewall, password, audit, and group policies
    /// </summary>
    public class SecurityPolicyMonitor
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();

        public ObservableCollection<SecurityPolicy> FirewallPolicies { get; private set; }
        public ObservableCollection<SecurityPolicy> PasswordPolicies { get; private set; }
        public ObservableCollection<SecurityPolicy> AuditPolicies { get; private set; }
        public ObservableCollection<SecurityPolicy> GroupPolicies { get; private set; }
        public DateTime LastCheckTime { get; private set; }
        public bool IsChecking { get; private set; }

        public event EventHandler<PolicyCheckCompletedEventArgs> PolicyCheckCompleted;
        public event EventHandler<PolicyCheckProgressEventArgs> PolicyCheckProgress;

        public SecurityPolicyMonitor()
        {
            FirewallPolicies = new ObservableCollection<SecurityPolicy>();
            PasswordPolicies = new ObservableCollection<SecurityPolicy>();
            AuditPolicies = new ObservableCollection<SecurityPolicy>();
            GroupPolicies = new ObservableCollection<SecurityPolicy>();
            LastCheckTime = DateTime.MinValue;
        }

        /// <summary>
        /// Asynchronously checks all security policies
        /// </summary>
        public async Task CheckAllPoliciesAsync()
        {
            if (IsChecking)
                return;

            try
            {
                IsChecking = true;
                FirewallPolicies.Clear();
                PasswordPolicies.Clear();
                AuditPolicies.Clear();
                GroupPolicies.Clear();

                OnPolicyCheckProgress("Initializing security policy check...", 0);

                await Task.Run(() =>
                {
                    // Check firewall policies
                    CheckFirewallPolicies();
                    OnPolicyCheckProgress("Checking firewall policies...", 25);

                    // Check password policies
                    CheckPasswordPolicies();
                    OnPolicyCheckProgress("Checking password policies...", 50);

                    // Check audit policies
                    CheckAuditPolicies();
                    OnPolicyCheckProgress("Checking audit policies...", 75);

                    // Check group policies
                    CheckGroupPolicies();
                    OnPolicyCheckProgress("Checking group policies...", 90);
                });

                LastCheckTime = DateTime.Now;
                OnPolicyCheckProgress("Policy check completed", 100);
                OnPolicyCheckCompleted(true, null);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking security policies: {ex.Message}");
                OnPolicyCheckCompleted(false, ex.Message);
            }
            finally
            {
                IsChecking = false;
            }
        }

        /// <summary>
        /// Checks Windows Firewall policies
        /// </summary>
        private void CheckFirewallPolicies()
        {
            try
            {
                // Check Windows Firewall status using PowerShell
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-NetFirewallProfile | Select-Object Name, Enabled\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Parse the output
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool readingData = false;
                    string currentProfile = null;

                    foreach (string line in lines)
                    {
                        if (line.Contains("----"))
                        {
                            readingData = true;
                            continue;
                        }

                        if (readingData)
                        {
                            string[] parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2)
                            {
                                currentProfile = parts[0];
                                bool enabled = parts[1].Equals("True", StringComparison.OrdinalIgnoreCase);

                                SecurityPolicy policy = new SecurityPolicy
                                {
                                    Name = $"{currentProfile} Firewall Profile",
                                    Category = PolicyCategory.Firewall,
                                    Value = enabled ? "Enabled" : "Disabled",
                                    Status = enabled ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                                    Description = $"Windows Firewall {currentProfile} profile status",
                                    RecommendedValue = "Enabled"
                                };

                                FirewallPolicies.Add(policy);
                            }
                        }
                    }
                }

                // Check firewall rules
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object {$_.Action -eq 'Allow'} | Measure-Object | Select-Object Count\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Parse the count
                    int inboundAllowRules = 0;
                    foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (line.Contains("Count"))
                            continue;

                        if (int.TryParse(line.Trim(), out int count))
                            inboundAllowRules = count;
                    }

                    SecurityPolicy policy = new SecurityPolicy
                    {
                        Name = "Inbound Allow Rules",
                        Category = PolicyCategory.Firewall,
                        Value = inboundAllowRules.ToString(),
                        Status = inboundAllowRules > 20 ? PolicyStatus.Warning : PolicyStatus.Compliant,
                        Description = "Number of enabled inbound allow rules",
                        RecommendedValue = "Minimize inbound allow rules"
                    };

                    FirewallPolicies.Add(policy);
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking firewall policies");
                AddErrorPolicy(FirewallPolicies, "Firewall Policies", ex.Message, PolicyCategory.Firewall);
            }
        }

        /// <summary>
        /// Checks Windows password policies
        /// </summary>
        private void CheckPasswordPolicies()
        {
            try
            {
                // Check password policies using PowerShell
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-ADDefaultDomainPasswordPolicy\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(error) && error.Contains("Get-ADDefaultDomainPasswordPolicy"))
                    {
                        // Fallback to net accounts if AD cmdlets are not available
                        CheckPasswordPoliciesWithNetAccounts();
                    }
                    else
                    {
                        // Parse the output
                        ParseADPasswordPolicies(output);
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking password policies");
                try
                {
                    // Fallback to net accounts
                    CheckPasswordPoliciesWithNetAccounts();
                }
                catch (Exception fallbackEx)
                {
                    _exceptionHandler.HandleException(fallbackEx, "Error checking password policies with fallback method");
                    AddErrorPolicy(PasswordPolicies, "Password Policies", ex.Message, PolicyCategory.Password);
                }
            }
        }

        /// <summary>
        /// Fallback method to check password policies using net accounts
        /// </summary>
        private void CheckPasswordPoliciesWithNetAccounts()
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "net";
                process.StartInfo.Arguments = "accounts";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse the output
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string line in lines)
                {
                    if (line.Contains("password age"))
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length >= 2)
                        {
                            string value = parts[1].Trim();
                            int days = 0;
                            if (int.TryParse(value.Split(' ')[0], out days))
                            {
                                SecurityPolicy policy = new SecurityPolicy
                                {
                                    Name = "Maximum Password Age",
                                    Category = PolicyCategory.Password,
                                    Value = $"{days} days",
                                    Status = days <= 90 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                                    Description = "Maximum password age before change is required",
                                    RecommendedValue = "90 days or less"
                                };

                                PasswordPolicies.Add(policy);
                            }
                        }
                    }
                    else if (line.Contains("length"))
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length >= 2)
                        {
                            string value = parts[1].Trim();
                            int length = 0;
                            if (int.TryParse(value, out length))
                            {
                                SecurityPolicy policy = new SecurityPolicy
                                {
                                    Name = "Minimum Password Length",
                                    Category = PolicyCategory.Password,
                                    Value = length.ToString(),
                                    Status = length >= 8 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                                    Description = "Minimum required password length",
                                    RecommendedValue = "8 or more characters"
                                };

                                PasswordPolicies.Add(policy);
                            }
                        }
                    }
                    else if (line.Contains("lockout threshold"))
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length >= 2)
                        {
                            string value = parts[1].Trim();
                            if (value.Contains("Never"))
                            {
                                SecurityPolicy policy = new SecurityPolicy
                                {
                                    Name = "Account Lockout Threshold",
                                    Category = PolicyCategory.Password,
                                    Value = "Never",
                                    Status = PolicyStatus.NonCompliant,
                                    Description = "Number of failed logon attempts before account is locked",
                                    RecommendedValue = "5 or fewer attempts"
                                };

                                PasswordPolicies.Add(policy);
                            }
                            else
                            {
                                int threshold = 0;
                                if (int.TryParse(value.Split(' ')[0], out threshold))
                                {
                                    SecurityPolicy policy = new SecurityPolicy
                                    {
                                        Name = "Account Lockout Threshold",
                                        Category = PolicyCategory.Password,
                                        Value = threshold.ToString(),
                                        Status = threshold <= 5 && threshold > 0 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                                        Description = "Number of failed logon attempts before account is locked",
                                        RecommendedValue = "5 or fewer attempts"
                                    };

                                    PasswordPolicies.Add(policy);
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Parses Active Directory password policies
        /// </summary>
        private void ParseADPasswordPolicies(string output)
        {
            string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            Dictionary<string, string> policyValues = new Dictionary<string, string>();

            foreach (string line in lines)
            {
                if (line.Contains(":"))
                {
                    string[] parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length == 2)
                    {
                        string key = parts[0].Trim();
                        string value = parts[1].Trim();
                        policyValues[key] = value;
                    }
                }
            }

            // Process the collected values
            if (policyValues.ContainsKey("MinPasswordLength"))
            {
                int length = 0;
                if (int.TryParse(policyValues["MinPasswordLength"], out length))
                {
                    SecurityPolicy policy = new SecurityPolicy
                    {
                        Name = "Minimum Password Length",
                        Category = PolicyCategory.Password,
                        Value = length.ToString(),
                        Status = length >= 8 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                        Description = "Minimum required password length",
                        RecommendedValue = "8 or more characters"
                    };

                    PasswordPolicies.Add(policy);
                }
            }

            if (policyValues.ContainsKey("MaxPasswordAge"))
            {
                string maxAge = policyValues["MaxPasswordAge"];
                if (maxAge.Contains("days"))
                {
                    int days = 0;
                    if (int.TryParse(maxAge.Split(' ')[0], out days))
                    {
                        SecurityPolicy policy = new SecurityPolicy
                        {
                            Name = "Maximum Password Age",
                            Category = PolicyCategory.Password,
                            Value = $"{days} days",
                            Status = days <= 90 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                            Description = "Maximum password age before change is required",
                            RecommendedValue = "90 days or less"
                        };

                        PasswordPolicies.Add(policy);
                    }
                }
            }

            if (policyValues.ContainsKey("LockoutThreshold"))
            {
                int threshold = 0;
                if (int.TryParse(policyValues["LockoutThreshold"], out threshold))
                {
                    SecurityPolicy policy = new SecurityPolicy
                    {
                        Name = "Account Lockout Threshold",
                        Category = PolicyCategory.Password,
                        Value = threshold.ToString(),
                        Status = threshold <= 5 && threshold > 0 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                        Description = "Number of failed logon attempts before account is locked",
                        RecommendedValue = "5 or fewer attempts"
                    };

                    PasswordPolicies.Add(policy);
                }
            }

            if (policyValues.ContainsKey("PasswordHistoryCount"))
            {
                int historyCount = 0;
                if (int.TryParse(policyValues["PasswordHistoryCount"], out historyCount))
                {
                    SecurityPolicy policy = new SecurityPolicy
                    {
                        Name = "Password History",
                        Category = PolicyCategory.Password,
                        Value = historyCount.ToString(),
                        Status = historyCount >= 10 ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                        Description = "Number of unique passwords before reuse",
                        RecommendedValue = "10 or more passwords"
                    };

                    PasswordPolicies.Add(policy);
                }
            }

            if (policyValues.ContainsKey("ComplexityEnabled"))
            {
                bool complexityEnabled = policyValues["ComplexityEnabled"].Equals("True", StringComparison.OrdinalIgnoreCase);
                SecurityPolicy policy = new SecurityPolicy
                {
                    Name = "Password Complexity",
                    Category = PolicyCategory.Password,
                    Value = complexityEnabled ? "Enabled" : "Disabled",
                    Status = complexityEnabled ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                    Description = "Password must meet complexity requirements",
                    RecommendedValue = "Enabled"
                };

                PasswordPolicies.Add(policy);
            }
        }

        /// <summary>
        /// Checks Windows audit policies
        /// </summary>
        private void CheckAuditPolicies()
        {
            try
            {
                // Check audit policies using PowerShell
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"auditpol /get /category:* /r | ConvertFrom-Csv\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Parse the output
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool readingData = false;

                    foreach (string line in lines)
                    {
                        if (line.Contains("Policy Target") || line.Contains("Subcategory"))
                        {
                            readingData = true;
                            continue;
                        }

                        if (readingData && !string.IsNullOrWhiteSpace(line))
                        {
                            string[] parts = line.Split(',');
                            if (parts.Length >= 3)
                            {
                                string subcategory = parts[1].Trim();
                                string setting = parts[2].Trim();

                                // Determine compliance status based on best practices
                                PolicyStatus status = PolicyStatus.Compliant;
                                string recommendedValue = "Success and Failure";

                                if (subcategory.Contains("Logon") || subcategory.Contains("Account Lockout") ||
                                    subcategory.Contains("User Account Management") || subcategory.Contains("Security Group Management") ||
                                    subcategory.Contains("Sensitive Privilege") || subcategory.Contains("Policy Change"))
                                {
                                    if (setting != "Success and Failure")
                                    {
                                        status = PolicyStatus.NonCompliant;
                                    }
                                }
                                else if (subcategory.Contains("Process Creation") || subcategory.Contains("Process Termination"))
                                {
                                    if (setting == "No Auditing")
                                    {
                                        status = PolicyStatus.NonCompliant;
                                        recommendedValue = "Success";
                                    }
                                }
                                else
                                {
                                    if (setting == "No Auditing")
                                    {
                                        status = PolicyStatus.Warning;
                                        recommendedValue = "At least Success";
                                    }
                                }

                                SecurityPolicy policy = new SecurityPolicy
                                {
                                    Name = subcategory,
                                    Category = PolicyCategory.Audit,
                                    Value = setting,
                                    Status = status,
                                    Description = $"Audit policy for {subcategory}",
                                    RecommendedValue = recommendedValue
                                };

                                AuditPolicies.Add(policy);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking audit policies");
                AddErrorPolicy(AuditPolicies, "Audit Policies", ex.Message, PolicyCategory.Audit);
            }
        }

        /// <summary>
        /// Checks Windows group policies
        /// </summary>
        private void CheckGroupPolicies()
        {
            try
            {
                // Check if Group Policy cmdlets are available
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-Command Get-GPO -ErrorAction SilentlyContinue\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(output))
                    {
                        // Group Policy cmdlets are available, get GPO information
                        CheckGroupPoliciesWithPowerShell();
                    }
                    else
                    {
                        // Fallback to checking specific security settings
                        CheckSecuritySettings();
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking group policies");
                try
                {
                    // Fallback to checking specific security settings
                    CheckSecuritySettings();
                }
                catch (Exception fallbackEx)
                {
                    _exceptionHandler.HandleException(fallbackEx, "Error checking security settings with fallback method");
                    AddErrorPolicy(GroupPolicies, "Group Policies", ex.Message, PolicyCategory.GroupPolicy);
                }
            }
        }

        /// <summary>
        /// Checks group policies using PowerShell
        /// </summary>
        private void CheckGroupPoliciesWithPowerShell()
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-Command \"Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Parse the output
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                bool readingData = false;

                foreach (string line in lines)
                {
                    if (line.Contains("DisplayName") || line.Contains("GpoStatus"))
                    {
                        readingData = true;
                        continue;
                    }

                    if (readingData && !string.IsNullOrWhiteSpace(line))
                    {
                        string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            string name = parts[0];
                            string status = parts[1];

                            for (int i = 2; i < parts.Length; i++)
                            {
                                if (!parts[i].Contains("/") && !parts[i].Contains(":"))
                                {
                                    name += " " + parts[i];
                                }
                                else
                                {
                                    break;
                                }
                            }

                            SecurityPolicy policy = new SecurityPolicy
                            {
                                Name = name,
                                Category = PolicyCategory.GroupPolicy,
                                Value = status,
                                Status = status.Equals("AllSettingsEnabled", StringComparison.OrdinalIgnoreCase) ? PolicyStatus.Compliant : PolicyStatus.Warning,
                                Description = $"Group Policy Object status",
                                RecommendedValue = "AllSettingsEnabled"
                            };

                            GroupPolicies.Add(policy);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Fallback method to check specific security settings
        /// </summary>
        private void CheckSecuritySettings()
        {
            // Check UAC settings
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA'\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                bool uacEnabled = output.Contains("EnableLUA") && output.Contains("1");
                SecurityPolicy policy = new SecurityPolicy
                {
                    Name = "User Account Control (UAC)",
                    Category = PolicyCategory.GroupPolicy,
                    Value = uacEnabled ? "Enabled" : "Disabled",
                    Status = uacEnabled ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                    Description = "User Account Control status",
                    RecommendedValue = "Enabled"
                };

                GroupPolicies.Add(policy);
            }

            // Check Windows Defender status
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                bool antivirusEnabled = output.Contains("AntivirusEnabled") && output.Contains("True");
                bool realtimeProtectionEnabled = output.Contains("RealTimeProtectionEnabled") && output.Contains("True");

                SecurityPolicy avPolicy = new SecurityPolicy
                {
                    Name = "Windows Defender Antivirus",
                    Category = PolicyCategory.GroupPolicy,
                    Value = antivirusEnabled ? "Enabled" : "Disabled",
                    Status = antivirusEnabled ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                    Description = "Windows Defender Antivirus status",
                    RecommendedValue = "Enabled"
                };

                SecurityPolicy rtPolicy = new SecurityPolicy
                {
                    Name = "Windows Defender Real-time Protection",
                    Category = PolicyCategory.GroupPolicy,
                    Value = realtimeProtectionEnabled ? "Enabled" : "Disabled",
                    Status = realtimeProtectionEnabled ? PolicyStatus.Compliant : PolicyStatus.NonCompliant,
                    Description = "Windows Defender Real-time Protection status",
                    RecommendedValue = "Enabled"
                };

                GroupPolicies.Add(avPolicy);
                GroupPolicies.Add(rtPolicy);
            }

            // Check automatic updates
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                bool autoUpdateDisabled = output.Contains("NoAutoUpdate") && output.Contains("1");
                SecurityPolicy policy = new SecurityPolicy
                {
                    Name = "Windows Automatic Updates",
                    Category = PolicyCategory.GroupPolicy,
                    Value = autoUpdateDisabled ? "Disabled" : "Enabled",
                    Status = autoUpdateDisabled ? PolicyStatus.NonCompliant : PolicyStatus.Compliant,
                    Description = "Windows Automatic Updates status",
                    RecommendedValue = "Enabled"
                };

                GroupPolicies.Add(policy);
            }
        }

        /// <summary>
        /// Adds an error policy to the collection
        /// </summary>
        private void AddErrorPolicy(ObservableCollection<SecurityPolicy> collection, string name, string errorMessage, PolicyCategory category)
        {
            SecurityPolicy policy = new SecurityPolicy
            {
                Name = name,
                Category = category,
                Value = "Error",
                Status = PolicyStatus.Error,
                Description = $"Error checking policies: {errorMessage}",
                RecommendedValue = "N/A"
            };

            collection.Add(policy);
        }

        /// <summary>
        /// Raises the PolicyCheckProgress event
        /// </summary>
        private void OnPolicyCheckProgress(string status, int percentComplete)
        {
            PolicyCheckProgress?.Invoke(this, new PolicyCheckProgressEventArgs(status, percentComplete));
        }

        /// <summary>
        /// Raises the PolicyCheckCompleted event
        /// </summary>
        private void OnPolicyCheckCompleted(bool success, string errorMessage)
        {
            PolicyCheckCompleted?.Invoke(this, new PolicyCheckCompletedEventArgs(success, errorMessage));
        }
    }

    /// <summary>
    /// Represents a security policy
    /// </summary>
    public class SecurityPolicy
    {
        public string Name { get; set; }
        public PolicyCategory Category { get; set; }
        public string Value { get; set; }
        public PolicyStatus Status { get; set; }
        public string Description { get; set; }
        public string RecommendedValue { get; set; }

        public string CategoryString => Category.ToString();
        public string StatusString => Status.ToString();
    }

    /// <summary>
    /// Categories of security policies
    /// </summary>
    public enum PolicyCategory
    {
        Firewall,
        Password,
        Audit,
        GroupPolicy
    }

    /// <summary>
    /// Status of security policies
    /// </summary>
    public enum PolicyStatus
    {
        Compliant,
        NonCompliant,
        Warning,
        Error,
        NotApplicable
    }

    /// <summary>
    /// Event arguments for policy check progress
    /// </summary>
    public class PolicyCheckProgressEventArgs : EventArgs
    {
        public string Status { get; }
        public int PercentComplete { get; }

        public PolicyCheckProgressEventArgs(string status, int percentComplete)
        {
            Status = status;
            PercentComplete = percentComplete;
        }
    }

    /// <summary>
    /// Event arguments for policy check completion
    /// </summary>
    public class PolicyCheckCompletedEventArgs : EventArgs
    {
        public bool Success { get; }
        public string ErrorMessage { get; }

        public PolicyCheckCompletedEventArgs(bool success, string errorMessage)
        {
            Success = success;
            ErrorMessage = errorMessage;
        }
    }
}