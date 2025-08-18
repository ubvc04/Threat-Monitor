using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Xml;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Compliance
{
    /// <summary>
    /// Checks for missing Windows updates and patches
    /// </summary>
    public class WindowsUpdateChecker
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();

        public ObservableCollection<WindowsUpdate> AvailableUpdates { get; private set; }
        public ObservableCollection<WindowsUpdate> InstalledUpdates { get; private set; }
        public DateTime LastCheckTime { get; private set; }
        public bool IsChecking { get; private set; }
        public int CriticalUpdateCount => AvailableUpdates?.Count(u => u.Severity == UpdateSeverity.Critical) ?? 0;
        public int SecurityUpdateCount => AvailableUpdates?.Count(u => u.Severity == UpdateSeverity.Security) ?? 0;
        public int ImportantUpdateCount => AvailableUpdates?.Count(u => u.Severity == UpdateSeverity.Important) ?? 0;

        public event EventHandler<UpdateCheckCompletedEventArgs> UpdateCheckCompleted;
        public event EventHandler<UpdateCheckProgressEventArgs> UpdateCheckProgress;

        public WindowsUpdateChecker()
        {
            AvailableUpdates = new ObservableCollection<WindowsUpdate>();
            InstalledUpdates = new ObservableCollection<WindowsUpdate>();
            LastCheckTime = DateTime.MinValue;
        }

        /// <summary>
        /// Asynchronously checks for Windows updates
        /// </summary>
        public async Task CheckForUpdatesAsync()
        {
            if (IsChecking)
                return;

            try
            {
                IsChecking = true;
                AvailableUpdates.Clear();
                InstalledUpdates.Clear();

                OnUpdateCheckProgress("Initializing Windows Update check...", 0);

                await Task.Run(() =>
                {
                    // Check for available updates using WMI
                    CheckAvailableUpdates();
                    OnUpdateCheckProgress("Checking available updates...", 50);

                    // Check for installed updates
                    CheckInstalledUpdates();
                    OnUpdateCheckProgress("Checking installed updates...", 90);
                });

                LastCheckTime = DateTime.Now;
                OnUpdateCheckProgress("Update check completed", 100);
                OnUpdateCheckCompleted(true, null);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error checking for Windows updates: {ex.Message}");
                OnUpdateCheckCompleted(false, ex.Message);
            }
            finally
            {
                IsChecking = false;
            }
        }

        /// <summary>
        /// Checks for available Windows updates using WMI
        /// </summary>
        private void CheckAvailableUpdates()
        {
            try
            {
                // Use Windows Update Agent API via COM
                Type updateSessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
                if (updateSessionType != null)
                {
                    dynamic updateSession = Activator.CreateInstance(updateSessionType);
                    dynamic updateSearcher = updateSession.CreateUpdateSearcher();
                    
                    // Search for updates
                    OnUpdateCheckProgress("Searching for updates...", 20);
                    dynamic searchResult = updateSearcher.Search("IsInstalled=0 and Type='Software'");
                    
                    // Process results
                    OnUpdateCheckProgress("Processing update results...", 40);
                    dynamic updates = searchResult.Updates;
                    
                    for (int i = 0; i < updates.Count; i++)
                    {
                        dynamic update = updates.Item(i);
                        WindowsUpdate windowsUpdate = new WindowsUpdate
                        {
                            Title = update.Title,
                            Description = update.Description,
                            KBArticleIDs = GetKBArticleIDs(update),
                            IsDownloaded = update.IsDownloaded,
                            Categories = GetUpdateCategories(update.Categories),
                            Severity = DetermineSeverity(update),
                            ReleaseDate = GetReleaseDate(update)
                        };
                        
                        AvailableUpdates.Add(windowsUpdate);
                    }
                }
                else
                {
                    // Fallback to using PowerShell if COM approach fails
                    CheckAvailableUpdatesWithPowerShell();
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking for available Windows updates");
                // Fallback to PowerShell method
                CheckAvailableUpdatesWithPowerShell();
            }
        }

        /// <summary>
        /// Fallback method to check for available updates using PowerShell
        /// </summary>
        private void CheckAvailableUpdatesWithPowerShell()
        {
            try
            {
                OnUpdateCheckProgress("Using PowerShell to check for updates...", 30);
                
                // Create PowerShell process to get updates
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-Command \"Get-WindowsUpdate -MicrosoftUpdate | ConvertTo-Json\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    if (!string.IsNullOrEmpty(output) && output.Trim() != "null")
                    {
                        // Parse JSON output and add updates
                        // This is simplified - in a real implementation, you would use JSON parsing
                        string[] updateLines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string line in updateLines)
                        {
                            if (line.Contains("KB") && line.Contains("Title"))
                            {
                                string title = line.Substring(line.IndexOf(":") + 1).Trim(' ', '"', ',');
                                WindowsUpdate update = new WindowsUpdate
                                {
                                    Title = title,
                                    Description = "Retrieved via PowerShell",
                                    Severity = DetermineSeverityFromTitle(title),
                                    ReleaseDate = DateTime.Now // Actual date not available in this simplified approach
                                };
                                
                                AvailableUpdates.Add(update);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking for available Windows updates with PowerShell");
                // Add a placeholder update to indicate the error
                AvailableUpdates.Add(new WindowsUpdate
                {
                    Title = "Error checking for updates",
                    Description = ex.Message,
                    Severity = UpdateSeverity.Unknown,
                    ReleaseDate = DateTime.Now
                });
            }
        }

        /// <summary>
        /// Checks for installed Windows updates
        /// </summary>
        private void CheckInstalledUpdates()
        {
            try
            {
                // Use WMI to query installed updates
                using (var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT * FROM Win32_QuickFixEngineering"))
                {
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        string hotfixId = queryObj["HotFixID"]?.ToString() ?? "Unknown";
                        string description = queryObj["Description"]?.ToString() ?? "";
                        string caption = queryObj["Caption"]?.ToString() ?? "";
                        DateTime installDate = DateTime.MinValue;
                        
                        if (queryObj["InstalledOn"] != null)
                        {
                            DateTime.TryParse(queryObj["InstalledOn"].ToString(), out installDate);
                        }
                        
                        WindowsUpdate update = new WindowsUpdate
                        {
                            Title = $"{description} ({hotfixId})",
                            Description = caption,
                            KBArticleIDs = new List<string> { hotfixId },
                            IsDownloaded = true,
                            IsInstalled = true,
                            Categories = new List<string> { "Installed Update" },
                            Severity = UpdateSeverity.Unknown, // Severity not available for installed updates
                            ReleaseDate = installDate
                        };
                        
                        InstalledUpdates.Add(update);
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error checking for installed Windows updates");
            }
        }

        /// <summary>
        /// Gets KB article IDs from an update
        /// </summary>
        private List<string> GetKBArticleIDs(dynamic update)
        {
            List<string> kbArticleIDs = new List<string>();
            try
            {
                if (update.KBArticleIDs != null && update.KBArticleIDs.Count > 0)
                {
                    for (int i = 0; i < update.KBArticleIDs.Count; i++)
                    {
                        kbArticleIDs.Add($"KB{update.KBArticleIDs.Item(i)}");
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error getting KB article IDs");
            }
            return kbArticleIDs;
        }

        /// <summary>
        /// Gets update categories from a collection
        /// </summary>
        private List<string> GetUpdateCategories(dynamic categories)
        {
            List<string> categoryList = new List<string>();
            try
            {
                if (categories != null && categories.Count > 0)
                {
                    for (int i = 0; i < categories.Count; i++)
                    {
                        categoryList.Add(categories.Item(i).Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error getting update categories");
            }
            return categoryList;
        }

        /// <summary>
        /// Determines the severity of an update
        /// </summary>
        private UpdateSeverity DetermineSeverity(dynamic update)
        {
            try
            {
                if (update.MsrcSeverity != null)
                {
                    string severity = update.MsrcSeverity.ToString().ToLower();
                    if (severity.Contains("critical"))
                        return UpdateSeverity.Critical;
                    if (severity.Contains("important"))
                        return UpdateSeverity.Important;
                    if (severity.Contains("moderate"))
                        return UpdateSeverity.Moderate;
                    if (severity.Contains("low"))
                        return UpdateSeverity.Low;
                }

                // Check categories for security updates
                for (int i = 0; i < update.Categories.Count; i++)
                {
                    string category = update.Categories.Item(i).Name.ToLower();
                    if (category.Contains("security") || category.Contains("critical"))
                        return UpdateSeverity.Security;
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error determining update severity");
            }
            
            return UpdateSeverity.Unknown;
        }

        /// <summary>
        /// Determines severity from update title (fallback method)
        /// </summary>
        private UpdateSeverity DetermineSeverityFromTitle(string title)
        {
            string lowerTitle = title.ToLower();
            if (lowerTitle.Contains("critical") || lowerTitle.Contains("security") || lowerTitle.Contains("vulnerability"))
                return UpdateSeverity.Critical;
            if (lowerTitle.Contains("important"))
                return UpdateSeverity.Important;
            if (lowerTitle.Contains("moderate"))
                return UpdateSeverity.Moderate;
            if (lowerTitle.Contains("low"))
                return UpdateSeverity.Low;
            
            return UpdateSeverity.Unknown;
        }

        /// <summary>
        /// Gets the release date of an update
        /// </summary>
        private DateTime GetReleaseDate(dynamic update)
        {
            try
            {
                if (update.LastDeploymentChangeTime != null)
                {
                    return update.LastDeploymentChangeTime;
                }
            }
            catch (Exception ex)
            {
                _exceptionHandler.HandleException(ex, "Error getting update release date");
            }
            
            return DateTime.MinValue;
        }

        /// <summary>
        /// Raises the UpdateCheckProgress event
        /// </summary>
        private void OnUpdateCheckProgress(string status, int percentComplete)
        {
            UpdateCheckProgress?.Invoke(this, new UpdateCheckProgressEventArgs(status, percentComplete));
        }

        /// <summary>
        /// Raises the UpdateCheckCompleted event
        /// </summary>
        private void OnUpdateCheckCompleted(bool success, string errorMessage)
        {
            UpdateCheckCompleted?.Invoke(this, new UpdateCheckCompletedEventArgs(success, errorMessage));
        }
    }

    /// <summary>
    /// Represents a Windows update
    /// </summary>
    public class WindowsUpdate
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public List<string> KBArticleIDs { get; set; } = new List<string>();
        public bool IsDownloaded { get; set; }
        public bool IsInstalled { get; set; }
        public List<string> Categories { get; set; } = new List<string>();
        public UpdateSeverity Severity { get; set; }
        public DateTime ReleaseDate { get; set; }

        public string SeverityString => Severity.ToString();
        public string KBArticleString => string.Join(", ", KBArticleIDs);
        public string CategoryString => string.Join(", ", Categories);
        public string ReleaseDateString => ReleaseDate > DateTime.MinValue ? ReleaseDate.ToShortDateString() : "Unknown";
    }

    /// <summary>
    /// Severity levels for Windows updates
    /// </summary>
    public enum UpdateSeverity
    {
        Unknown,
        Low,
        Moderate,
        Important,
        Security,
        Critical
    }

    /// <summary>
    /// Event arguments for update check progress
    /// </summary>
    public class UpdateCheckProgressEventArgs : EventArgs
    {
        public string Status { get; }
        public int PercentComplete { get; }

        public UpdateCheckProgressEventArgs(string status, int percentComplete)
        {
            Status = status;
            PercentComplete = percentComplete;
        }
    }

    /// <summary>
    /// Event arguments for update check completion
    /// </summary>
    public class UpdateCheckCompletedEventArgs : EventArgs
    {
        public bool Success { get; }
        public string ErrorMessage { get; }

        public UpdateCheckCompletedEventArgs(bool success, string errorMessage)
        {
            Success = success;
            ErrorMessage = errorMessage;
        }
    }
}