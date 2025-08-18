using System;
using System.Management;
using Microsoft.Win32;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.System
{
    public class SystemMonitor
    {
        private readonly Logger _logger;

        public string WindowsVersion { get; private set; }
        public string WindowsBuild { get; private set; }
        public string WindowsArchitecture { get; private set; }
        public DateTime InstallDate { get; private set; }
        public string LastBootUpTime { get; private set; }

        public SystemMonitor()
        {
            _logger = Logger.Instance;
            _logger.LogDebug("SystemMonitor initialized");
        }

        public void RefreshSystemInfo()
        {
            try
            {
                _logger.LogDebug("Refreshing system information");
                GetWindowsVersionInfo();
                GetLastBootTime();
                _logger.LogInformation($"System information refreshed: {WindowsVersion} (Build {WindowsBuild})");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing system information");
            }
        }

        private void GetWindowsVersionInfo()
        {
            try
            {
                // Get Windows version from Registry
                using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (registryKey != null)
                    {
                        string productName = registryKey.GetValue("ProductName")?.ToString() ?? "Unknown";
                        string releaseId = registryKey.GetValue("ReleaseId")?.ToString() ?? "Unknown";
                        string currentBuild = registryKey.GetValue("CurrentBuild")?.ToString() ?? "Unknown";
                        string ubr = registryKey.GetValue("UBR")?.ToString() ?? "Unknown";

                        WindowsVersion = $"{productName} ({releaseId})";
                        WindowsBuild = $"{currentBuild}.{ubr}";
                    }
                }

                // Get system architecture
                WindowsArchitecture = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";

                // Get install date
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT InstallDate FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        if (os["InstallDate"] != null)
                        {
                            string installDateString = os["InstallDate"].ToString();
                            if (DateTime.TryParseExact(
                                installDateString.Substring(0, 14),
                                "yyyyMMddHHmmss",
                                System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.None,
                                out DateTime installDate))
                            {
                                InstallDate = installDate;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting Windows version information");
                WindowsVersion = "Unknown";
                WindowsBuild = "Unknown";
                WindowsArchitecture = "Unknown";
            }
        }

        private void GetLastBootTime()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        if (os["LastBootUpTime"] != null)
                        {
                            string bootTimeString = os["LastBootUpTime"].ToString();
                            if (DateTime.TryParseExact(
                                bootTimeString.Substring(0, 14),
                                "yyyyMMddHHmmss",
                                System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.None,
                                out DateTime bootTime))
                            {
                                LastBootUpTime = bootTime.ToString("g");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting last boot time");
                LastBootUpTime = "Unknown";
            }
        }
    }
}