using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Compliance
{
    /// <summary>
    /// Checks for outdated software on the system
    /// </summary>
    public class SoftwareVersionChecker
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly HttpClient _httpClient;

        public ObservableCollection<SoftwareInfo> InstalledSoftware { get; private set; }
        public DateTime LastCheckTime { get; private set; }
        public bool IsChecking { get; private set; }
        public int OutdatedSoftwareCount => InstalledSoftware?.Count(s => s.Status == SoftwareStatus.Outdated) ?? 0;
        public int VulnerableSoftwareCount => InstalledSoftware?.Count(s => s.Status == SoftwareStatus.Vulnerable) ?? 0;

        public event EventHandler<SoftwareCheckCompletedEventArgs> SoftwareCheckCompleted;
        public event EventHandler<SoftwareCheckProgressEventArgs> SoftwareCheckProgress;

        // Dictionary of known software with their latest versions
        private Dictionary<string, string> _knownSoftwareVersions;

        // Dictionary of known vulnerable software versions
        private Dictionary<string, List<string>> _knownVulnerableVersions;

        public SoftwareVersionChecker()
        {
            InstalledSoftware = new ObservableCollection<SoftwareInfo>();
            LastCheckTime = DateTime.MinValue;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "WinSecMonitor/1.0");
            InitializeKnownSoftwareVersions();
            InitializeKnownVulnerableVersions();
        }

        /// <summary>
        /// Asynchronously checks for outdated software
        /// </summary>
        public async Task CheckSoftwareAsync()
        {
            if (IsChecking)
                return;

            try
            {
                IsChecking = true;
                InstalledSoftware.Clear();

                OnSoftwareCheckProgress("Initializing software check...", 0);

                await Task.Run(() =>
                {
                    // Get installed software
                    GetInstalledSoftware();
                    OnSoftwareCheckProgress("Checking installed software...", 50);

                    // Check for outdated software
                    CheckForOutdatedSoftware();
                    OnSoftwareCheckProgress("Checking for outdated software...", 90);
                });

                LastCheckTime = DateTime.Now;
                OnSoftwareCheckProgress("Software check completed", 100);
                OnSoftwareCheckCompleted(true, null);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking for outdated software: {ex.Message}");
                OnSoftwareCheckCompleted(false, ex.Message);
            }
            finally
            {
                IsChecking = false;
            }
        }

        /// <summary>
        /// Gets installed software from the registry
        /// </summary>
        private void GetInstalledSoftware()
        {
            try
            {
                // Use WMI to query installed software
                using (var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT * FROM Win32_Product"))
                {
                    OnSoftwareCheckProgress("Retrieving installed software...", 10);
                    
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        string name = queryObj["Name"]?.ToString() ?? "Unknown";
                        string version = queryObj["Version"]?.ToString() ?? "Unknown";
                        string vendor = queryObj["Vendor"]?.ToString() ?? "Unknown";
                        string installDate = queryObj["InstallDate"]?.ToString() ?? "Unknown";
                        
                        SoftwareInfo software = new SoftwareInfo
                        {
                            Name = name,
                            Version = version,
                            Vendor = vendor,
                            InstallDate = ParseInstallDate(installDate),
                            Status = SoftwareStatus.Unknown
                        };
                        
                        InstalledSoftware.Add(software);
                    }
                }

                // Also check Programs and Features for software that might not be in WMI
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null }\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    // Parse the output
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool readingData = false;
                    string currentName = null;
                    string currentVersion = null;
                    string currentPublisher = null;
                    string currentInstallDate = null;
                    
                    foreach (string line in lines)
                    {
                        if (line.Contains("DisplayName") || line.Contains("DisplayVersion"))
                        {
                            readingData = true;
                            continue;
                        }
                        
                        if (readingData)
                        {
                            if (line.Trim().StartsWith("DisplayName"))
                            {
                                // Save previous software if we have one
                                if (currentName != null && !InstalledSoftware.Any(s => s.Name == currentName && s.Version == currentVersion))
                                {
                                    SoftwareInfo software = new SoftwareInfo
                                    {
                                        Name = currentName,
                                        Version = currentVersion ?? "Unknown",
                                        Vendor = currentPublisher ?? "Unknown",
                                        InstallDate = ParseInstallDate(currentInstallDate),
                                        Status = SoftwareStatus.Unknown
                                    };
                                    
                                    InstalledSoftware.Add(software);
                                }
                                
                                // Start new software
                                currentName = line.Substring(line.IndexOf(':') + 1).Trim();
                                currentVersion = null;
                                currentPublisher = null;
                                currentInstallDate = null;
                            }
                            else if (line.Trim().StartsWith("DisplayVersion") && currentName != null)
                            {
                                currentVersion = line.Substring(line.IndexOf(':') + 1).Trim();
                            }
                            else if (line.Trim().StartsWith("Publisher") && currentName != null)
                            {
                                currentPublisher = line.Substring(line.IndexOf(':') + 1).Trim();
                            }
                            else if (line.Trim().StartsWith("InstallDate") && currentName != null)
                            {
                                currentInstallDate = line.Substring(line.IndexOf(':') + 1).Trim();
                            }
                        }
                    }
                    
                    // Add the last software if we have one
                    if (currentName != null && !InstalledSoftware.Any(s => s.Name == currentName && s.Version == currentVersion))
                    {
                        SoftwareInfo software = new SoftwareInfo
                        {
                            Name = currentName,
                            Version = currentVersion ?? "Unknown",
                            Vendor = currentPublisher ?? "Unknown",
                            InstallDate = ParseInstallDate(currentInstallDate),
                            Status = SoftwareStatus.Unknown
                        };
                        
                        InstalledSoftware.Add(software);
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error getting installed software");
            }
        }

        /// <summary>
        /// Checks for outdated software by comparing versions
        /// </summary>
        private void CheckForOutdatedSoftware()
        {
            try
            {
                int count = 0;
                int total = InstalledSoftware.Count;
                
                foreach (SoftwareInfo software in InstalledSoftware)
                {
                    count++;
                    if (count % 10 == 0)
                    {
                        OnSoftwareCheckProgress($"Checking software {count} of {total}...", 50 + (count * 40 / total));
                    }
                    
                    // Check if this is known software
                    string normalizedName = NormalizeSoftwareName(software.Name);
                    string latestVersion = null;
                    
                    foreach (var knownSoftware in _knownSoftwareVersions)
                    {
                        if (normalizedName.Contains(knownSoftware.Key.ToLower()))
                        {
                            latestVersion = knownSoftware.Value;
                            break;
                        }
                    }
                    
                    if (latestVersion != null)
                    {
                        // Compare versions
                        if (CompareVersions(software.Version, latestVersion) < 0)
                        {
                            software.Status = SoftwareStatus.Outdated;
                            software.LatestVersion = latestVersion;
                        }
                        else
                        {
                            software.Status = SoftwareStatus.UpToDate;
                            software.LatestVersion = latestVersion;
                        }
                    }
                    else
                    {
                        software.Status = SoftwareStatus.Unknown;
                    }
                    
                    // Check if this is a known vulnerable version
                    CheckForVulnerableVersion(software);
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking for outdated software");
            }
        }

        /// <summary>
        /// Checks if the software version is known to be vulnerable
        /// </summary>
        private void CheckForVulnerableVersion(SoftwareInfo software)
        {
            try
            {
                string normalizedName = NormalizeSoftwareName(software.Name);
                
                foreach (var vulnerableSoftware in _knownVulnerableVersions)
                {
                    if (normalizedName.Contains(vulnerableSoftware.Key.ToLower()))
                    {
                        foreach (string vulnerableVersion in vulnerableSoftware.Value)
                        {
                            if (software.Version.Equals(vulnerableVersion, StringComparison.OrdinalIgnoreCase) ||
                                (vulnerableVersion.Contains("*") && IsVersionMatch(software.Version, vulnerableVersion)))
                            {
                                software.Status = SoftwareStatus.Vulnerable;
                                software.VulnerabilityInfo = $"Known vulnerable version of {vulnerableSoftware.Key}"; 
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking for vulnerable software version");
            }
        }

        /// <summary>
        /// Initializes the dictionary of known software versions
        /// </summary>
        private void InitializeKnownSoftwareVersions()
        {
            _knownSoftwareVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "Google Chrome", "122.0.6261.69" },
                { "Mozilla Firefox", "123.0" },
                { "Microsoft Edge", "122.0.2365.66" },
                { "Adobe Acrobat Reader", "23.006.20320" },
                { "Adobe Acrobat", "23.006.20320" },
                { "7-Zip", "23.01" },
                { "VLC media player", "3.0.20" },
                { "Java", "8.0.401" },
                { "Oracle Java", "8.0.401" },
                { "OpenJDK", "21.0.2" },
                { "Microsoft Office", "16.0.16130.20314" },
                { "Notepad++", "8.6.4" },
                { "WinRAR", "6.24" },
                { "Python", "3.12.2" },
                { "Node.js", "21.6.2" },
                { "Visual Studio Code", "1.87.0" },
                { "Visual Studio", "17.8.6" },
                { "TeamViewer", "15.48.4" },
                { "Zoom", "5.17.5" },
                { "Skype", "8.110.0.215" },
                { "Slack", "4.36.140" },
                { "Discord", "1.0.9028" },
                { "Steam", "2.10.91.91" },
                { "iTunes", "12.12.10.9" },
                { "Spotify", "1.2.31.1061" },
                { "Dropbox", "188.4.5273" },
                { "OneDrive", "24.002.0103.0005" },
                { "Google Drive", "84.0.0.0" },
                { "NVIDIA GeForce Experience", "3.27.0.112" },
                { "AMD Radeon Software", "23.12.1" },
                { "Intel Graphics Driver", "31.0.101.4502" },
                { "Malwarebytes", "4.6.0.4255" },
                { "Avast", "23.2.6001" },
                { "AVG", "23.2.6001" },
                { "Norton", "23.23.10.16" },
                { "McAfee", "16.0.49" },
                { "Kaspersky", "21.3.10.391" },
                { "Bitdefender", "26.0.22.84" },
                { "ESET", "16.1.2.0" },
                { "Webroot", "9.0.35.50" },
                { "CCleaner", "6.18.10610" },
                { "Foxit Reader", "12.1.2.15332" },
                { "Audacity", "3.4.2" },
                { "GIMP", "2.10.36" },
                { "Inkscape", "1.3.2" },
                { "Blender", "4.0.2" },
                { "OBS Studio", "30.0.2" },
                { "FileZilla", "3.66.4" },
                { "PuTTY", "0.80" },
                { "WinSCP", "6.3.2" },
                { "Git", "2.43.0" },
                { "VMware Workstation", "17.5.0" },
                { "VirtualBox", "7.0.14" },
                { "Docker Desktop", "4.27.2" },
                { "PowerShell", "7.4.1" },
                { "Windows Terminal", "1.18.10301.0" },
                { "Microsoft SQL Server Management Studio", "19.2" },
                { "MySQL Workbench", "8.0.36" },
                { "PostgreSQL", "16.1" },
                { "MongoDB", "7.0.5" },
                { "Redis", "7.2.4" },
                { "Wireshark", "4.2.3" },
                { "Nmap", "7.94" },
                { "Fiddler", "5.0.20231.16108" },
                { "Postman", "10.23.0" },
                { "Insomnia", "8.6.1" },
                { "Android Studio", "2023.1.1.27" },
                { "Xcode", "15.2" },
                { "Eclipse", "2023-12" },
                { "IntelliJ IDEA", "2023.3.4" },
                { "PyCharm", "2023.3.4" },
                { "WebStorm", "2023.3.4" },
                { "PhpStorm", "2023.3.4" },
                { "Rider", "2023.3.4" },
                { "GoLand", "2023.3.4" },
                { "CLion", "2023.3.4" },
                { "RubyMine", "2023.3.4" },
                { "DataGrip", "2023.3.4" },
                { "AppCode", "2023.3.4" },
                { "Unity", "2022.3.19" },
                { "Unreal Engine", "5.3.2" },
                { "Godot", "4.2.1" },
                { "Krita", "5.2.2" },
                { "DaVinci Resolve", "18.6.4" },
                { "Adobe Photoshop", "25.5.0" },
                { "Adobe Illustrator", "28.0.0" },
                { "Adobe Premiere Pro", "24.0" },
                { "Adobe After Effects", "24.0" },
                { "Adobe InDesign", "19.0" },
                { "Adobe Lightroom", "13.0.1" },
                { "Adobe XD", "56.1.12.1" },
                { "Autodesk AutoCAD", "2024.1.2" },
                { "Autodesk Maya", "2024.2" },
                { "Autodesk 3ds Max", "2024.2" },
                { "Autodesk Revit", "2024.1.1" },
                { "Autodesk Fusion 360", "2.0.17836" },
                { "SketchUp", "23.1.337" },
                { "Rhino", "7.33.24059.15001" },
                { "SolidWorks", "2024 SP1.0" },
                { "MATLAB", "R2023b" },
                { "R", "4.3.2" },
                { "RStudio", "2023.12.1.402" },
                { "Anaconda", "2023.09-0" },
                { "Jupyter", "7.0.7" },
                { "Tableau", "2023.4.1" },
                { "Power BI Desktop", "2.126.927.0" },
                { "Looker Studio", "1.0.0" },
                { "QuickBooks", "2024.1.0" },
                { "SAP", "7.50" },
                { "Salesforce", "248.0" },
                { "Zoom", "5.17.5" },
                { "Microsoft Teams", "24.02.00.08" },
                { "Slack", "4.36.140" },
                { "Discord", "1.0.9028" },
                { "WhatsApp", "2.2404.5.0" },
                { "Telegram", "4.14.0" },
                { "Signal", "6.44.0" },
                { "Skype", "8.110.0.215" },
                { "Cisco Webex", "43.3.0.26940" },
                { "GoToMeeting", "10.19.0" },
                { "Trello", "2.12.8" },
                { "Asana", "1.7.0" },
                { "Jira", "9.12.0" },
                { "Confluence", "8.5.3" },
                { "Notion", "2.0.41" },
                { "Evernote", "10.72.2" },
                { "OneNote", "16.0.16130.20314" },
                { "Obsidian", "1.5.3" },
                { "Todoist", "8.12.0" },
                { "Microsoft To Do", "2.107.54842.0" },
                { "Bitwarden", "2024.2.0" },
                { "LastPass", "4.123.0" },
                { "1Password", "8.10.20" },
                { "KeePass", "2.54" },
                { "Dashlane", "6.2346.0" },
                { "NordVPN", "7.15.0" },
                { "ExpressVPN", "12.72.0" },
                { "Surfshark", "4.13.0" },
                { "ProtonVPN", "3.2.8" },
                { "CyberGhost", "8.12.8" },
                { "Private Internet Access", "3.5.4" },
                { "TunnelBear", "5.1.0" },
                { "Mullvad", "2023.6" },
                { "WireGuard", "0.5.3" },
                { "OpenVPN", "2.6.8" },
                { "Tor Browser", "13.0.8" },
                { "Brave Browser", "1.62.153" },
                { "Opera", "107.0.5045.36" },
                { "Vivaldi", "6.5.3206.63" },
                { "Safari", "17.3" },
                { "Internet Explorer", "11.0.220" },
                { "Thunderbird", "115.7.0" },
                { "Microsoft Outlook", "16.0.16130.20314" },
                { "Gmail", "2024.02.04.0" },
                { "Apple Mail", "17.0" },
                { "ProtonMail", "2.0.0" },
                { "Tutanota", "3.118.3" },
                { "Mailbird", "2.9.68" },
                { "eM Client", "9.2.2093" },
                { "The Bat!", "10.4.4" },
                { "Windows Defender", "4.18.2402.7" },
                { "Microsoft Security Essentials", "4.18.2402.7" },
                { "Windows Security", "4.18.2402.7" }
            };
        }

        /// <summary>
        /// Initializes the dictionary of known vulnerable software versions
        /// </summary>
        private void InitializeKnownVulnerableVersions()
        {
            _knownVulnerableVersions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
            {
                { "Google Chrome", new List<string> { "121.*", "120.*", "119.*", "118.*", "117.*", "116.*", "115.*", "114.*", "113.*", "112.*" } },
                { "Mozilla Firefox", new List<string> { "122.*", "121.*", "120.*", "119.*", "118.*", "117.*", "116.*", "115.*", "114.*", "113.*" } },
                { "Microsoft Edge", new List<string> { "121.*", "120.*", "119.*", "118.*", "117.*", "116.*", "115.*", "114.*", "113.*", "112.*" } },
                { "Adobe Acrobat Reader", new List<string> { "22.*", "21.*", "20.*", "19.*", "18.*", "17.*" } },
                { "Adobe Acrobat", new List<string> { "22.*", "21.*", "20.*", "19.*", "18.*", "17.*" } },
                { "Java", new List<string> { "8.0.391", "8.0.381", "8.0.371", "8.0.361", "8.0.351", "8.0.341" } },
                { "Oracle Java", new List<string> { "8.0.391", "8.0.381", "8.0.371", "8.0.361", "8.0.351", "8.0.341" } },
                { "OpenJDK", new List<string> { "20.*", "19.*", "18.*", "17.0.8", "17.0.7", "17.0.6", "17.0.5" } },
                { "Microsoft Office", new List<string> { "16.0.16026.*", "16.0.15928.*", "16.0.15831.*", "16.0.15726.*" } },
                { "VLC media player", new List<string> { "3.0.19", "3.0.18", "3.0.17", "3.0.16" } },
                { "7-Zip", new List<string> { "22.*", "21.*", "20.*", "19.*" } },
                { "Zoom", new List<string> { "5.16.*", "5.15.*", "5.14.*", "5.13.*" } },
                { "TeamViewer", new List<string> { "15.47.*", "15.46.*", "15.45.*", "15.44.*" } },
                { "Notepad++", new List<string> { "8.5.*", "8.4.*", "8.3.*", "8.2.*" } },
                { "WinRAR", new List<string> { "6.23", "6.22", "6.21", "6.20", "6.10", "6.00" } },
                { "Python", new List<string> { "3.11.7", "3.11.6", "3.11.5", "3.11.4", "3.10.*", "3.9.*", "3.8.*", "3.7.*" } },
                { "Node.js", new List<string> { "21.5.*", "21.4.*", "21.3.*", "21.2.*", "20.*", "19.*", "18.*", "17.*" } },
                { "Visual Studio Code", new List<string> { "1.86.*", "1.85.*", "1.84.*", "1.83.*" } },
                { "Visual Studio", new List<string> { "17.8.5", "17.8.4", "17.8.3", "17.8.2", "17.8.1", "17.8.0" } },
                { "Git", new List<string> { "2.42.*", "2.41.*", "2.40.*", "2.39.*" } },
                { "Docker Desktop", new List<string> { "4.26.*", "4.25.*", "4.24.*", "4.23.*" } },
                { "VMware Workstation", new List<string> { "17.0.*", "16.*", "15.*" } },
                { "VirtualBox", new List<string> { "7.0.12", "7.0.10", "7.0.8", "7.0.6" } },
                { "Wireshark", new List<string> { "4.2.2", "4.2.1", "4.2.0", "4.0.*", "3.*" } },
                { "Putty", new List<string> { "0.79", "0.78", "0.77", "0.76" } },
                { "FileZilla", new List<string> { "3.65.*", "3.64.*", "3.63.*", "3.62.*" } },
                { "WinSCP", new List<string> { "6.2.*", "6.1.*", "6.0.*", "5.*" } },
                { "Dropbox", new List<string> { "187.*", "186.*", "185.*", "184.*" } },
                { "OneDrive", new List<string> { "23.*", "22.*", "21.*" } },
                { "Google Drive", new List<string> { "83.*", "82.*", "81.*", "80.*" } },
                { "Malwarebytes", new List<string> { "4.5.*", "4.4.*", "4.3.*", "4.2.*" } },
                { "Avast", new List<string> { "22.*", "21.*", "20.*" } },
                { "AVG", new List<string> { "22.*", "21.*", "20.*" } },
                { "Norton", new List<string> { "22.*", "21.*", "20.*" } },
                { "McAfee", new List<string> { "15.*", "14.*", "13.*" } },
                { "Kaspersky", new List<string> { "20.*", "19.*", "18.*" } },
                { "Bitdefender", new List<string> { "25.*", "24.*", "23.*" } },
                { "ESET", new List<string> { "15.*", "14.*", "13.*" } },
                { "CCleaner", new List<string> { "6.17.*", "6.16.*", "6.15.*", "6.14.*" } },
                { "Foxit Reader", new List<string> { "12.0.*", "11.*", "10.*" } },
                { "OBS Studio", new List<string> { "29.*", "28.*", "27.*" } },
                { "PowerShell", new List<string> { "7.3.*", "7.2.*", "7.1.*", "7.0.*" } },
                { "Windows Terminal", new List<string> { "1.17.*", "1.16.*", "1.15.*", "1.14.*" } },
                { "Tor Browser", new List<string> { "13.0.7", "13.0.6", "13.0.5", "13.0.4" } },
                { "Brave Browser", new List<string> { "1.61.*", "1.60.*", "1.59.*", "1.58.*" } },
                { "Opera", new List<string> { "106.*", "105.*", "104.*", "103.*" } },
                { "Vivaldi", new List<string> { "6.4.*", "6.3.*", "6.2.*", "6.1.*" } },
                { "Thunderbird", new List<string> { "115.6.*", "115.5.*", "115.4.*", "115.3.*" } },
                { "Skype", new List<string> { "8.109.*", "8.108.*", "8.107.*", "8.106.*" } },
                { "Slack", new List<string> { "4.35.*", "4.34.*", "4.33.*", "4.32.*" } },
                { "Discord", new List<string> { "1.0.9027", "1.0.9026", "1.0.9025", "1.0.9024" } },
                { "Microsoft Teams", new List<string> { "24.01.*", "23.12.*", "23.11.*", "23.10.*" } },
                { "WhatsApp", new List<string> { "2.2403.*", "2.2402.*", "2.2401.*", "2.2312.*" } },
                { "Telegram", new List<string> { "4.13.*", "4.12.*", "4.11.*", "4.10.*" } },
                { "Signal", new List<string> { "6.43.*", "6.42.*", "6.41.*", "6.40.*" } },
                { "Bitwarden", new List<string> { "2024.1.*", "2023.12.*", "2023.11.*", "2023.10.*" } },
                { "LastPass", new List<string> { "4.122.*", "4.121.*", "4.120.*", "4.119.*" } },
                { "1Password", new List<string> { "8.10.19", "8.10.18", "8.10.17", "8.10.16" } },
                { "KeePass", new List<string> { "2.53", "2.52", "2.51", "2.50" } },
                { "NordVPN", new List<string> { "7.14.*", "7.13.*", "7.12.*", "7.11.*" } },
                { "ExpressVPN", new List<string> { "12.71.*", "12.70.*", "12.69.*", "12.68.*" } },
                { "Surfshark", new List<string> { "4.12.*", "4.11.*", "4.10.*", "4.9.*" } },
                { "ProtonVPN", new List<string> { "3.2.7", "3.2.6", "3.2.5", "3.2.4" } },
                { "Windows Defender", new List<string> { "4.18.2312.*", "4.18.2311.*", "4.18.2310.*", "4.18.2309.*" } }
            };
        }

        /// <summary>
        /// Normalizes a software name for comparison
        /// </summary>
        private string NormalizeSoftwareName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return string.Empty;
                
            return name.ToLower()
                .Replace("microsoft", "")
                .Replace("corporation", "")
                .Replace("inc.", "")
                .Replace("inc", "")
                .Replace("llc", "")
                .Replace("ltd", "")
                .Replace("software", "")
                .Replace("technologies", "")
                .Replace("technology", "")
                .Replace("(x86)", "")
                .Replace("(x64)", "")
                .Replace("64-bit", "")
                .Replace("32-bit", "")
                .Replace("  ", " ")
                .Trim();
        }

        /// <summary>
        /// Compares two version strings
        /// </summary>
        private int CompareVersions(string version1, string version2)
        {
            if (version1 == null || version2 == null)
                return 0;
                
            if (version1 == "Unknown" || version2 == "Unknown")
                return 0;
                
            try
            {
                // Extract version numbers
                string v1 = ExtractVersionNumbers(version1);
                string v2 = ExtractVersionNumbers(version2);
                
                // Split into components
                string[] v1Parts = v1.Split('.');
                string[] v2Parts = v2.Split('.');
                
                // Compare each component
                int maxLength = Math.Max(v1Parts.Length, v2Parts.Length);
                
                for (int i = 0; i < maxLength; i++)
                {
                    int v1Component = i < v1Parts.Length ? int.Parse(v1Parts[i]) : 0;
                    int v2Component = i < v2Parts.Length ? int.Parse(v2Parts[i]) : 0;
                    
                    if (v1Component < v2Component)
                        return -1;
                    if (v1Component > v2Component)
                        return 1;
                }
                
                return 0;
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error comparing versions");
                return 0;
            }
        }

        /// <summary>
        /// Extracts version numbers from a string
        /// </summary>
        private string ExtractVersionNumbers(string version)
        {
            if (string.IsNullOrEmpty(version))
                return "0.0.0.0";
                
            // Extract digits and dots
            string result = "";
            bool lastWasDigitOrDot = false;
            
            foreach (char c in version)
            {
                if (char.IsDigit(c) || c == '.')
                {
                    result += c;
                    lastWasDigitOrDot = true;
                }
                else if (lastWasDigitOrDot && c == ' ')
                {
                    break;
                }
            }
            
            // Ensure we have at least one digit
            if (string.IsNullOrEmpty(result) || !result.Any(char.IsDigit))
                return "0.0.0.0";
                
            // Remove trailing dots
            result = result.TrimEnd('.');
            
            // Ensure we have at least one dot
            if (!result.Contains("."))
                result += ".0";
                
            return result;
        }

        /// <summary>
        /// Checks if a version matches a pattern with wildcards
        /// </summary>
        private bool IsVersionMatch(string version, string pattern)
        {
            if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(pattern))
                return false;
                
            // Replace * with regex wildcard
            string regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(version, regexPattern);
        }

        /// <summary>
        /// Parses an install date string
        /// </summary>
        private DateTime ParseInstallDate(string installDate)
        {
            if (string.IsNullOrEmpty(installDate))
                return DateTime.MinValue;
                
            // Try to parse YYYYMMDD format
            if (installDate.Length == 8 && int.TryParse(installDate, out _))
            {
                try
                {
                    int year = int.Parse(installDate.Substring(0, 4));
                    int month = int.Parse(installDate.Substring(4, 2));
                    int day = int.Parse(installDate.Substring(6, 2));
                    
                    return new DateTime(year, month, day);
                }
                catch
                {
                    return DateTime.MinValue;
                }
            }
            
            // Try standard date parsing
            DateTime result;
            if (DateTime.TryParse(installDate, out result))
                return result;
                
            return DateTime.MinValue;
        }

        /// <summary>
        /// Raises the SoftwareCheckProgress event
        /// </summary>
        private void OnSoftwareCheckProgress(string status, int percentComplete)
        {
            SoftwareCheckProgress?.Invoke(this, new SoftwareCheckProgressEventArgs(status, percentComplete));
        }

        /// <summary>
        /// Raises the SoftwareCheckCompleted event
        /// </summary>
        private void OnSoftwareCheckCompleted(bool success, string errorMessage)
        {
            SoftwareCheckCompleted?.Invoke(this, new SoftwareCheckCompletedEventArgs(success, errorMessage));
        }
    }

    /// <summary>
    /// Represents installed software information
    /// </summary>
    public class SoftwareInfo
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Vendor { get; set; }
        public DateTime InstallDate { get; set; }
        public SoftwareStatus Status { get; set; }
        public string LatestVersion { get; set; }
        public string VulnerabilityInfo { get; set; }

        public string StatusString => Status.ToString();
        public string InstallDateString => InstallDate > DateTime.MinValue ? InstallDate.ToShortDateString() : "Unknown";
    }

    /// <summary>
    /// Status of software
    /// </summary>
    public enum SoftwareStatus
    {
        Unknown,
        UpToDate,
        Outdated,
        Vulnerable
    }

    /// <summary>
    /// Event arguments for software check progress
    /// </summary>
    public class SoftwareCheckProgressEventArgs : EventArgs
    {
        public string Status { get; }
        public int PercentComplete { get; }

        public SoftwareCheckProgressEventArgs(string status, int percentComplete)
        {
            Status = status;
            PercentComplete = percentComplete;
        }
    }

    /// <summary>
    /// Event arguments for software check completion
    /// </summary>
    public class SoftwareCheckCompletedEventArgs : EventArgs
    {
        public bool Success { get; }
        public string ErrorMessage { get; }

        public SoftwareCheckCompletedEventArgs(bool success, string errorMessage)
        {
            Success = success;
            ErrorMessage = errorMessage;
        }
    }
}