using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Timers;
using Microsoft.Win32;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.EventLog
{
    /// <summary>
    /// Provides advanced rootkit detection capabilities
    /// </summary>
    public class RootkitDetector
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();
        private readonly Timer _scanTimer;
        private readonly List<string> _knownRootkitSignatures = new List<string>();
        private readonly List<string> _knownRootkitRegistryKeys = new List<string>();
        private readonly List<string> _knownRootkitFileLocations = new List<string>();
        private readonly List<string> _knownRootkitProcessNames = new List<string>();

        /// <summary>
        /// Event raised when a rootkit is detected
        /// </summary>
        public event EventHandler<RootkitDetectionEventArgs> RootkitDetected;

        /// <summary>
        /// Event raised when a scan is completed
        /// </summary>
        public event EventHandler<RootkitScanCompletedEventArgs> ScanCompleted;

        /// <summary>
        /// Event raised when a scan error occurs
        /// </summary>
        public event EventHandler<RootkitScanErrorEventArgs> ScanError;

        /// <summary>
        /// Gets or sets the scan interval in milliseconds
        /// </summary>
        public int ScanIntervalMs { get; set; }

        /// <summary>
        /// Gets a value indicating whether a scan is in progress
        /// </summary>
        public bool IsScanning { get; private set; }

        /// <summary>
        /// Gets the last scan time
        /// </summary>
        public DateTime LastScanTime { get; private set; }

        /// <summary>
        /// Gets the total number of detections
        /// </summary>
        public int TotalDetections { get; private set; }

        /// <summary>
        /// Gets or sets a value indicating whether to scan for hidden processes
        /// </summary>
        public bool ScanHiddenProcesses { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to scan for hidden files
        /// </summary>
        public bool ScanHiddenFiles { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to scan for hidden registry entries
        /// </summary>
        public bool ScanHiddenRegistry { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to scan for SSDT hooks
        /// </summary>
        public bool ScanSSDTHooks { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether to scan for kernel hooks
        /// </summary>
        public bool ScanKernelHooks { get; set; } = false;

        /// <summary>
        /// Initializes a new instance of the RootkitDetector class
        /// </summary>
        /// <param name="scanIntervalMs">The scan interval in milliseconds</param>
        public RootkitDetector(int scanIntervalMs = 3600000) // Default to 1 hour
        {
            ScanIntervalMs = scanIntervalMs;

            // Initialize scan timer
            _scanTimer = new Timer(ScanIntervalMs);
            _scanTimer.Elapsed += ScanTimer_Elapsed;
            _scanTimer.AutoReset = true;

            // Initialize known rootkit signatures
            InitializeKnownRootkitSignatures();

            _logger.LogInfo("RootkitDetector initialized");
        }

        /// <summary>
        /// Starts the rootkit detection scans
        /// </summary>
        public void Start()
        {
            if (!_scanTimer.Enabled)
            {
                _scanTimer.Start();
                _logger.LogInfo("Rootkit detection scans started");
            }
        }

        /// <summary>
        /// Stops the rootkit detection scans
        /// </summary>
        public void Stop()
        {
            if (_scanTimer.Enabled)
            {
                _scanTimer.Stop();
                _logger.LogInfo("Rootkit detection scans stopped");
            }
        }

        /// <summary>
        /// Performs a full rootkit scan
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task<RootkitScanResult> ScanAsync()
        {
            if (IsScanning)
            {
                _logger.LogWarning("Rootkit scan already in progress");
                return null;
            }

            IsScanning = true;
            var result = new RootkitScanResult
            {
                ScanStartTime = DateTime.Now,
                Detections = new List<RootkitDetection>()
            };

            try
            {
                _logger.LogInfo("Starting rootkit scan");

                // Perform the various scan types
                if (ScanHiddenProcesses)
                {
                    var hiddenProcesses = await ScanForHiddenProcessesAsync();
                    result.Detections.AddRange(hiddenProcesses);
                }

                if (ScanHiddenFiles)
                {
                    var hiddenFiles = await ScanForHiddenFilesAsync();
                    result.Detections.AddRange(hiddenFiles);
                }

                if (ScanHiddenRegistry)
                {
                    var hiddenRegistry = await ScanForHiddenRegistryEntriesAsync();
                    result.Detections.AddRange(hiddenRegistry);
                }

                if (ScanSSDTHooks)
                {
                    var ssdtHooks = await ScanForSSDTHooksAsync();
                    result.Detections.AddRange(ssdtHooks);
                }

                if (ScanKernelHooks)
                {
                    var kernelHooks = await ScanForKernelHooksAsync();
                    result.Detections.AddRange(kernelHooks);
                }

                // Update scan result
                result.ScanEndTime = DateTime.Now;
                result.ScanDurationMs = (int)(result.ScanEndTime - result.ScanStartTime).TotalMilliseconds;
                result.IsSuccess = true;

                // Update class properties
                LastScanTime = DateTime.Now;
                TotalDetections += result.Detections.Count;

                // Trigger events for each detection
                foreach (var detection in result.Detections)
                {
                    OnRootkitDetected(detection);
                }

                _logger.LogInfo($"Rootkit scan completed. Found {result.Detections.Count} suspicious items.");
                OnScanCompleted(result);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during rootkit scan: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error during rootkit scan");

                result.IsSuccess = false;
                result.ErrorMessage = ex.Message;
                result.ScanEndTime = DateTime.Now;
                result.ScanDurationMs = (int)(result.ScanEndTime - result.ScanStartTime).TotalMilliseconds;

                OnScanError("Full scan", ex.Message);

                return result;
            }
            finally
            {
                IsScanning = false;
            }
        }

        /// <summary>
        /// Scans for hidden processes
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        private async Task<List<RootkitDetection>> ScanForHiddenProcessesAsync()
        {
            var detections = new List<RootkitDetection>();

            try
            {
                _logger.LogInfo("Scanning for hidden processes");

                // Get processes using different methods and compare results
                var processesFromWMI = await GetProcessesFromWMIAsync();
                var processesFromAPI = GetProcessesFromAPI();

                // Find processes that are in WMI but not in API (potentially hidden)
                var hiddenProcesses = processesFromWMI.Except(processesFromAPI).ToList();

                // Check for known rootkit process names
                foreach (var process in processesFromWMI)
                {
                    if (_knownRootkitProcessNames.Any(p => process.ToLower().Contains(p.ToLower())))
                    {
                        var detection = new RootkitDetection
                        {
                            Type = RootkitDetectionType.SuspiciousProcess,
                            Severity = RootkitSeverity.High,
                            Location = process,
                            Description = $"Known rootkit process name detected: {process}",
                            DetectionTime = DateTime.Now
                        };

                        detections.Add(detection);
                    }
                }

                // Add hidden processes to detections
                foreach (var process in hiddenProcesses)
                {
                    var detection = new RootkitDetection
                    {
                        Type = RootkitDetectionType.HiddenProcess,
                        Severity = RootkitSeverity.High,
                        Location = process,
                        Description = $"Hidden process detected: {process}",
                        DetectionTime = DateTime.Now
                    };

                    detections.Add(detection);
                }

                _logger.LogInfo($"Found {detections.Count} suspicious processes");
                return detections;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for hidden processes: {ex.Message}");
                OnScanError("Hidden processes scan", ex.Message);
                return detections;
            }
        }

        /// <summary>
        /// Gets processes from WMI
        /// </summary>
        /// <returns>A list of process names</returns>
        private async Task<List<string>> GetProcessesFromWMIAsync()
        {
            var processes = new List<string>();

            await Task.Run(() =>
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process"))
                    {
                        foreach (var process in searcher.Get())
                        {
                            var processName = process["Name"]?.ToString();
                            if (!string.IsNullOrEmpty(processName))
                            {
                                processes.Add(processName);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error getting processes from WMI: {ex.Message}");
                }
            });

            return processes;
        }

        /// <summary>
        /// Gets processes from the Windows API
        /// </summary>
        /// <returns>A list of process names</returns>
        private List<string> GetProcessesFromAPI()
        {
            var processes = new List<string>();

            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        processes.Add(process.ProcessName + ".exe");
                    }
                    catch
                    {
                        // Ignore errors for individual processes
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting processes from API: {ex.Message}");
            }

            return processes;
        }

        /// <summary>
        /// Scans for hidden files
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        private async Task<List<RootkitDetection>> ScanForHiddenFilesAsync()
        {
            var detections = new List<RootkitDetection>();

            try
            {
                _logger.LogInfo("Scanning for hidden files");

                // Check system directories for hidden files with suspicious attributes
                var systemDirs = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
                };

                foreach (var dir in systemDirs)
                {
                    await Task.Run(() =>
                    {
                        try
                        {
                            // Check for files with suspicious attributes
                            var files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly);
                            foreach (var file in files)
                            {
                                try
                                {
                                    var fileInfo = new FileInfo(file);
                                    if ((fileInfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden &&
                                        (fileInfo.Attributes & FileAttributes.System) == FileAttributes.System)
                                    {
                                        // Check if the file matches known rootkit signatures
                                        if (_knownRootkitFileLocations.Any(s => file.ToLower().Contains(s.ToLower())))
                                        {
                                            var detection = new RootkitDetection
                                            {
                                                Type = RootkitDetectionType.SuspiciousFile,
                                                Severity = RootkitSeverity.High,
                                                Location = file,
                                                Description = $"Known rootkit file location: {file}",
                                                DetectionTime = DateTime.Now
                                            };

                                            detections.Add(detection);
                                        }
                                        else
                                        {
                                            var detection = new RootkitDetection
                                            {
                                                Type = RootkitDetectionType.HiddenFile,
                                                Severity = RootkitSeverity.Medium,
                                                Location = file,
                                                Description = $"Hidden system file detected: {file}",
                                                DetectionTime = DateTime.Now
                                            };

                                            detections.Add(detection);
                                        }
                                    }
                                }
                                catch
                                {
                                    // Ignore errors for individual files
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Error scanning directory {dir}: {ex.Message}");
                        }
                    });
                }

                // Check for alternate data streams (ADS) in system files
                await ScanForAlternateDataStreamsAsync(detections);

                _logger.LogInfo($"Found {detections.Count} suspicious files");
                return detections;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for hidden files: {ex.Message}");
                OnScanError("Hidden files scan", ex.Message);
                return detections;
            }
        }

        /// <summary>
        /// Scans for alternate data streams (ADS)
        /// </summary>
        /// <param name="detections">The list of detections to add to</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ScanForAlternateDataStreamsAsync(List<RootkitDetection> detections)
        {
            try
            {
                _logger.LogInfo("Scanning for alternate data streams");

                // Use PowerShell to detect alternate data streams
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-Command "Get-Item -Path 'C:\\Windows\\*' -Stream * | Where-Object {$_.Stream -ne ':$DATA'} | Select-Object FileName, Stream",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = new Process { StartInfo = startInfo };
                process.Start();

                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Parse the output to find alternate data streams
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (line.Contains("FileName") || line.Contains("----"))
                    {
                        continue; // Skip header lines
                    }

                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        var fileName = parts[0];
                        var streamName = parts[1];

                        var detection = new RootkitDetection
                        {
                            Type = RootkitDetectionType.AlternateDataStream,
                            Severity = RootkitSeverity.Medium,
                            Location = $"{fileName}:{streamName}",
                            Description = $"Alternate data stream detected: {fileName}:{streamName}",
                            DetectionTime = DateTime.Now
                        };

                        detections.Add(detection);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error scanning for alternate data streams: {ex.Message}");
            }
        }

        /// <summary>
        /// Scans for hidden registry entries
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        private async Task<List<RootkitDetection>> ScanForHiddenRegistryEntriesAsync()
        {
            var detections = new List<RootkitDetection>();

            try
            {
                _logger.LogInfo("Scanning for hidden registry entries");

                // Check for known rootkit registry keys
                await Task.Run(() =>
                {
                    try
                    {
                        // Check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
                        using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                        {
                            if (key != null)
                            {
                                foreach (var valueName in key.GetValueNames())
                                {
                                    var value = key.GetValue(valueName)?.ToString();
                                    if (!string.IsNullOrEmpty(value))
                                    {
                                        // Check if the value matches known rootkit signatures
                                        if (_knownRootkitSignatures.Any(s => value.ToLower().Contains(s.ToLower())))
                                        {
                                            var detection = new RootkitDetection
                                            {
                                                Type = RootkitDetectionType.SuspiciousRegistry,
                                                Severity = RootkitSeverity.High,
                                                Location = $"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{valueName}",
                                                Description = $"Suspicious autorun entry: {valueName} = {value}",
                                                DetectionTime = DateTime.Now
                                            };

                                            detections.Add(detection);
                                        }
                                    }
                                }
                            }
                        }

                        // Check for known rootkit registry keys
                        foreach (var registryKey in _knownRootkitRegistryKeys)
                        {
                            try
                            {
                                using (var key = Registry.LocalMachine.OpenSubKey(registryKey))
                                {
                                    if (key != null)
                                    {
                                        var detection = new RootkitDetection
                                        {
                                            Type = RootkitDetectionType.SuspiciousRegistry,
                                            Severity = RootkitSeverity.High,
                                            Location = $"HKLM\\{registryKey}",
                                            Description = $"Known rootkit registry key: {registryKey}",
                                            DetectionTime = DateTime.Now
                                        };

                                        detections.Add(detection);
                                    }
                                }
                            }
                            catch
                            {
                                // Ignore errors for individual registry keys
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error scanning registry: {ex.Message}");
                    }
                });

                _logger.LogInfo($"Found {detections.Count} suspicious registry entries");
                return detections;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for hidden registry entries: {ex.Message}");
                OnScanError("Hidden registry scan", ex.Message);
                return detections;
            }
        }

        /// <summary>
        /// Scans for SSDT hooks
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        private async Task<List<RootkitDetection>> ScanForSSDTHooksAsync()
        {
            var detections = new List<RootkitDetection>();

            try
            {
                _logger.LogInfo("Scanning for SSDT hooks");

                // Note: SSDT hook detection requires a kernel-mode driver
                // This is a placeholder implementation that would use a third-party tool

                await Task.Run(() =>
                {
                    try
                    {
                        // Check if we have admin rights
                        if (!IsAdministrator())
                        {
                            _logger.LogWarning("SSDT hook detection requires administrator privileges");
                            return;
                        }

                        // In a real implementation, this would use a kernel-mode driver or a third-party tool
                        // For this example, we'll just log that the scan was attempted
                        _logger.LogInfo("SSDT hook detection requires a kernel-mode driver (not implemented)");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error scanning for SSDT hooks: {ex.Message}");
                    }
                });

                return detections;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for SSDT hooks: {ex.Message}");
                OnScanError("SSDT hooks scan", ex.Message);
                return detections;
            }
        }

        /// <summary>
        /// Scans for kernel hooks
        /// </summary>
        /// <returns>A list of rootkit detections</returns>
        private async Task<List<RootkitDetection>> ScanForKernelHooksAsync()
        {
            var detections = new List<RootkitDetection>();

            try
            {
                _logger.LogInfo("Scanning for kernel hooks");

                // Note: Kernel hook detection requires a kernel-mode driver
                // This is a placeholder implementation that would use a third-party tool

                await Task.Run(() =>
                {
                    try
                    {
                        // Check if we have admin rights
                        if (!IsAdministrator())
                        {
                            _logger.LogWarning("Kernel hook detection requires administrator privileges");
                            return;
                        }

                        // In a real implementation, this would use a kernel-mode driver or a third-party tool
                        // For this example, we'll just log that the scan was attempted
                        _logger.LogInfo("Kernel hook detection requires a kernel-mode driver (not implemented)");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error scanning for kernel hooks: {ex.Message}");
                    }
                });

                return detections;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error scanning for kernel hooks: {ex.Message}");
                OnScanError("Kernel hooks scan", ex.Message);
                return detections;
            }
        }

        /// <summary>
        /// Checks if the current process is running with administrator privileges
        /// </summary>
        /// <returns>True if the process is running as administrator, false otherwise</returns>
        private bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Initializes known rootkit signatures
        /// </summary>
        private void InitializeKnownRootkitSignatures()
        {
            try
            {
                // Known rootkit process names
                _knownRootkitProcessNames.AddRange(new[]
                {
                    "ardamax",
                    "blazingtools",
                    "hacker",
                    "keylogger",
                    "spyagent",
                    "spytech",
                    "wireshark",
                    "netstat",
                    "processhacker",
                    "tcpview",
                    "filemon",
                    "procmon",
                    "regmon",
                    "processhacker",
                    "autoruns",
                    "autorunsc",
                    "sysinternal",
                    "system32.exe", // Fake system32 executable
                    "svch0st.exe", // Misspelled svchost
                    "explorer.exe.exe", // Double extension
                    "lsas.exe", // Misspelled lsass
                    "scvhost.exe", // Misspelled svchost
                    "csrss.exe" // When not in system32
                });

                // Known rootkit registry keys
                _knownRootkitRegistryKeys.AddRange(new[]
                {
                    @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableSecurityFilters",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe",
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
                });

                // Known rootkit file locations
                _knownRootkitFileLocations.AddRange(new[]
                {
                    @"\system32\drivers\etc\hosts.bak",
                    @"\system32\drivers\etc\hosts.old",
                    @"\system32\drivers\etc\hosts.sav",
                    @"\system32\drivers\null.sys",
                    @"\system32\drivers\beep.sys",
                    @"\system32\winsrv.dll",
                    @"\system32\drivers\rootkit",
                    @"\system32\drivers\svchost.exe",
                    @"\system32\explorer.exe.exe",
                    @"\system32\lsas.exe",
                    @"\system32\scvhost.exe"
                });

                // Known rootkit signatures (strings that might be found in files or registry)
                _knownRootkitSignatures.AddRange(new[]
                {
                    "rootkit",
                    "backdoor",
                    "trojan",
                    "keylogger",
                    "spyware",
                    "stealth",
                    "hidden",
                    "intercept",
                    "hook",
                    "inject",
                    "capture",
                    "spy",
                    "monitor",
                    "record",
                    "log keys",
                    "screen capture",
                    "screenshot",
                    "password steal",
                    "credential",
                    "exfiltrate",
                    "command and control",
                    "c&c",
                    "c2",
                    "beacon"
                });

                _logger.LogInfo("Initialized known rootkit signatures");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing rootkit signatures: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the scan timer elapsed event
        /// </summary>
        private async void ScanTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            _scanTimer.Stop();

            try
            {
                await ScanAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in scan timer: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error in rootkit scan timer");
            }
            finally
            {
                _scanTimer.Start();
            }
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
        /// Raises the ScanCompleted event
        /// </summary>
        /// <param name="result">The scan result</param>
        protected virtual void OnScanCompleted(RootkitScanResult result)
        {
            ScanCompleted?.Invoke(this, new RootkitScanCompletedEventArgs(result));
        }

        /// <summary>
        /// Raises the ScanError event
        /// </summary>
        /// <param name="scanType">The scan type</param>
        /// <param name="errorMessage">The error message</param>
        protected virtual void OnScanError(string scanType, string errorMessage)
        {
            ScanError?.Invoke(this, new RootkitScanErrorEventArgs(scanType, errorMessage));
        }
    }

    /// <summary>
    /// Represents a rootkit detection
    /// </summary>
    public class RootkitDetection
    {
        /// <summary>
        /// Gets or sets the detection type
        /// </summary>
        public RootkitDetectionType Type { get; set; }

        /// <summary>
        /// Gets or sets the detection severity
        /// </summary>
        public RootkitSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the detection location
        /// </summary>
        public string Location { get; set; }

        /// <summary>
        /// Gets or sets the detection description
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets the detection time
        /// </summary>
        public DateTime DetectionTime { get; set; }
    }

    /// <summary>
    /// Represents the type of a rootkit detection
    /// </summary>
    public enum RootkitDetectionType
    {
        /// <summary>
        /// Hidden process
        /// </summary>
        HiddenProcess,

        /// <summary>
        /// Suspicious process
        /// </summary>
        SuspiciousProcess,

        /// <summary>
        /// Hidden file
        /// </summary>
        HiddenFile,

        /// <summary>
        /// Suspicious file
        /// </summary>
        SuspiciousFile,

        /// <summary>
        /// Alternate data stream
        /// </summary>
        AlternateDataStream,

        /// <summary>
        /// Hidden registry entry
        /// </summary>
        HiddenRegistry,

        /// <summary>
        /// Suspicious registry entry
        /// </summary>
        SuspiciousRegistry,

        /// <summary>
        /// SSDT hook
        /// </summary>
        SSDTHook,

        /// <summary>
        /// Kernel hook
        /// </summary>
        KernelHook
    }

    /// <summary>
    /// Represents the severity of a rootkit detection
    /// </summary>
    public enum RootkitSeverity
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
    /// Represents the result of a rootkit scan
    /// </summary>
    public class RootkitScanResult
    {
        /// <summary>
        /// Gets or sets the scan start time
        /// </summary>
        public DateTime ScanStartTime { get; set; }

        /// <summary>
        /// Gets or sets the scan end time
        /// </summary>
        public DateTime ScanEndTime { get; set; }

        /// <summary>
        /// Gets or sets the scan duration in milliseconds
        /// </summary>
        public int ScanDurationMs { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the scan was successful
        /// </summary>
        public bool IsSuccess { get; set; }

        /// <summary>
        /// Gets or sets the error message
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Gets or sets the list of detections
        /// </summary>
        public List<RootkitDetection> Detections { get; set; } = new List<RootkitDetection>();
    }

    /// <summary>
    /// Event arguments for the RootkitDetected event
    /// </summary>
    public class RootkitDetectionEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the rootkit detection
        /// </summary>
        public RootkitDetection Detection { get; }

        /// <summary>
        /// Initializes a new instance of the RootkitDetectionEventArgs class
        /// </summary>
        /// <param name="detection">The rootkit detection</param>
        public RootkitDetectionEventArgs(RootkitDetection detection)
        {
            Detection = detection;
        }
    }

    /// <summary>
    /// Event arguments for the ScanCompleted event
    /// </summary>
    public class RootkitScanCompletedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the scan result
        /// </summary>
        public RootkitScanResult Result { get; }

        /// <summary>
        /// Initializes a new instance of the RootkitScanCompletedEventArgs class
        /// </summary>
        /// <param name="result">The scan result</param>
        public RootkitScanCompletedEventArgs(RootkitScanResult result)
        {
            Result = result;
        }
    }

    /// <summary>
    /// Event arguments for the ScanError event
    /// </summary>
    public class RootkitScanErrorEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the scan type
        /// </summary>
        public string ScanType { get; }

        /// <summary>
        /// Gets the error message
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of the RootkitScanErrorEventArgs class
        /// </summary>
        /// <param name="scanType">The scan type</param>
        /// <param name="errorMessage">The error message</param>
        public RootkitScanErrorEventArgs(string scanType, string errorMessage)
        {
            ScanType = scanType;
            ErrorMessage = errorMessage;
        }
    }
}