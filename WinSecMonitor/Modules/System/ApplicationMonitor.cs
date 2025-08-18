using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.System
{
    public class ApplicationMonitor
    {
        private readonly Logger _logger;
        public List<ApplicationInfo> InstalledApplications { get; private set; }

        public ApplicationMonitor()
        {
            _logger = Logger.Instance;
            InstalledApplications = new List<ApplicationInfo>();
            _logger.LogDebug("ApplicationMonitor initialized");
        }

        public async Task RefreshInstalledApplicationsAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing installed applications list");
                await Task.Run(() => GetInstalledApplications());
                _logger.LogInformation($"Found {InstalledApplications.Count} installed applications");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing installed applications");
            }
        }

        private void GetInstalledApplications()
        {
            try
            {
                InstalledApplications.Clear();
                var applications = new List<ApplicationInfo>();

                // Check both 32-bit and 64-bit registry locations
                applications.AddRange(GetApplicationsFromRegistry(RegistryView.Registry32));
                
                if (Environment.Is64BitOperatingSystem)
                {
                    applications.AddRange(GetApplicationsFromRegistry(RegistryView.Registry64));
                }

                // Remove duplicates based on application name
                InstalledApplications = applications
                    .GroupBy(app => app.Name)
                    .Select(group => group.First())
                    .OrderBy(app => app.Name)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting installed applications");
            }
        }

        private List<ApplicationInfo> GetApplicationsFromRegistry(RegistryView registryView)
        {
            var applications = new List<ApplicationInfo>();

            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView))
                {
                    using (RegistryKey uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                    {
                        if (uninstallKey != null)
                        {
                            foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                            {
                                using (RegistryKey subKey = uninstallKey.OpenSubKey(subKeyName))
                                {
                                    if (subKey != null)
                                    {
                                        // Skip system components and updates
                                        if (subKey.GetValue("SystemComponent") is int systemComponent && systemComponent == 1)
                                        {
                                            continue;
                                        }

                                        string displayName = subKey.GetValue("DisplayName")?.ToString();
                                        if (string.IsNullOrEmpty(displayName))
                                        {
                                            continue;
                                        }

                                        string displayVersion = subKey.GetValue("DisplayVersion")?.ToString() ?? "Unknown";
                                        string publisher = subKey.GetValue("Publisher")?.ToString() ?? "Unknown";
                                        string installDate = subKey.GetValue("InstallDate")?.ToString() ?? "";
                                        string installLocation = subKey.GetValue("InstallLocation")?.ToString() ?? "";
                                        string uninstallString = subKey.GetValue("UninstallString")?.ToString() ?? "";

                                        DateTime? parsedInstallDate = null;
                                        if (!string.IsNullOrEmpty(installDate) && installDate.Length == 8)
                                        {
                                            if (DateTime.TryParseExact(
                                                installDate,
                                                "yyyyMMdd",
                                                System.Globalization.CultureInfo.InvariantCulture,
                                                System.Globalization.DateTimeStyles.None,
                                                out DateTime date))
                                            {
                                                parsedInstallDate = date;
                                            }
                                        }

                                        applications.Add(new ApplicationInfo
                                        {
                                            Name = displayName,
                                            Version = displayVersion,
                                            Publisher = publisher,
                                            InstallDate = parsedInstallDate,
                                            InstallLocation = installLocation,
                                            UninstallString = uninstallString,
                                            Is64Bit = registryView == RegistryView.Registry64
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, $"Error accessing registry with view {registryView}");
            }

            return applications;
        }
    }

    public class ApplicationInfo
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public DateTime? InstallDate { get; set; }
        public string InstallLocation { get; set; }
        public string UninstallString { get; set; }
        public bool Is64Bit { get; set; }

        public string FormattedInstallDate => InstallDate.HasValue ? InstallDate.Value.ToShortDateString() : "Unknown";
        public string Architecture => Is64Bit ? "64-bit" : "32-bit";
    }
}