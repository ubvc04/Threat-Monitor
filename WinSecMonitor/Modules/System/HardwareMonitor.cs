using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.System
{
    public class HardwareMonitor
    {
        private readonly Logger _logger;
        private readonly PerformanceCounter _cpuCounter;
        private readonly PerformanceCounter _ramCounter;

        public float CpuUsage { get; private set; }
        public float RamUsage { get; private set; }
        public long TotalRam { get; private set; }
        public long AvailableRam { get; private set; }
        public List<DiskInfo> Disks { get; private set; }
        public List<NetworkAdapterInfo> NetworkAdapters { get; private set; }

        public HardwareMonitor()
        {
            _logger = Logger.Instance;
            _logger.LogDebug("HardwareMonitor initialized");

            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _ramCounter = new PerformanceCounter("Memory", "% Committed Bytes In Use");
                
                // First call to NextValue() always returns 0, so call it once during initialization
                _cpuCounter.NextValue();
                _ramCounter.NextValue();

                Disks = new List<DiskInfo>();
                NetworkAdapters = new List<NetworkAdapterInfo>();

                // Get total RAM
                GetTotalRam();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing HardwareMonitor");
            }
        }

        public async Task RefreshHardwareInfoAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing hardware information");

                // CPU and RAM usage can be retrieved quickly
                CpuUsage = _cpuCounter.NextValue();
                RamUsage = _ramCounter.NextValue();
                GetAvailableRam();

                // These operations might take longer, so run them in parallel
                await Task.WhenAll(
                    Task.Run(() => RefreshDiskInfo()),
                    Task.Run(() => RefreshNetworkAdapters())
                );

                _logger.LogInformation($"Hardware information refreshed: CPU: {CpuUsage:F1}%, RAM: {RamUsage:F1}%");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing hardware information");
            }
        }

        private void GetTotalRam()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        if (os["TotalVisibleMemorySize"] != null)
                        {
                            // Value is in KB, convert to bytes
                            TotalRam = Convert.ToInt64(os["TotalVisibleMemorySize"]) * 1024;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting total RAM");
                TotalRam = 0;
            }
        }

        private void GetAvailableRam()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT FreePhysicalMemory FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject os in searcher.Get())
                    {
                        if (os["FreePhysicalMemory"] != null)
                        {
                            // Value is in KB, convert to bytes
                            AvailableRam = Convert.ToInt64(os["FreePhysicalMemory"]) * 1024;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting available RAM");
                AvailableRam = 0;
            }
        }

        private void RefreshDiskInfo()
        {
            try
            {
                Disks.Clear();

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        string driveLetter = disk["DeviceID"].ToString();
                        string volumeName = disk["VolumeName"]?.ToString() ?? "";
                        long freeSpace = Convert.ToInt64(disk["FreeSpace"] ?? 0);
                        long totalSize = Convert.ToInt64(disk["Size"] ?? 0);

                        Disks.Add(new DiskInfo
                        {
                            DriveLetter = driveLetter,
                            VolumeName = volumeName,
                            TotalSize = totalSize,
                            FreeSpace = freeSpace,
                            UsedSpace = totalSize - freeSpace,
                            UsagePercentage = totalSize > 0 ? (float)((totalSize - freeSpace) * 100.0 / totalSize) : 0
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing disk information");
            }
        }

        private void RefreshNetworkAdapters()
        {
            try
            {
                NetworkAdapters.Clear();

                // Get network adapters using NetworkInterface class
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface ni in interfaces)
                {
                    // Skip loopback, tunnel adapters, and disconnected adapters
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.Description.Contains("Tunnel") ||
                        ni.OperationalStatus != OperationalStatus.Up)
                    {
                        continue;
                    }

                    IPv4InterfaceStatistics stats = ni.GetIPv4Statistics();

                    NetworkAdapterInfo adapter = new NetworkAdapterInfo
                    {
                        Name = ni.Name,
                        Description = ni.Description,
                        Type = ni.NetworkInterfaceType.ToString(),
                        Status = ni.OperationalStatus.ToString(),
                        Speed = ni.Speed,
                        BytesSent = stats.BytesSent,
                        BytesReceived = stats.BytesReceived,
                        MacAddress = string.Join("-", ni.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")))
                    };

                    // Get IP addresses
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            adapter.IPv4Address = ip.Address.ToString();
                            adapter.SubnetMask = ip.IPv4Mask.ToString();
                        }
                    }

                    NetworkAdapters.Add(adapter);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing network adapters");
            }
        }
    }

    public class DiskInfo
    {
        public string DriveLetter { get; set; }
        public string VolumeName { get; set; }
        public long TotalSize { get; set; }
        public long FreeSpace { get; set; }
        public long UsedSpace { get; set; }
        public float UsagePercentage { get; set; }

        public string FormattedTotalSize => FormatBytes(TotalSize);
        public string FormattedFreeSpace => FormatBytes(FreeSpace);
        public string FormattedUsedSpace => FormatBytes(UsedSpace);

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB" };
            int counter = 0;
            decimal number = bytes;

            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }

            return $"{number:n1} {suffixes[counter]}";
        }
    }

    public class NetworkAdapterInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        public string Status { get; set; }
        public long Speed { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public string MacAddress { get; set; }
        public string IPv4Address { get; set; }
        public string SubnetMask { get; set; }

        public string FormattedSpeed => FormatBits(Speed);
        public string FormattedBytesSent => FormatBytes(BytesSent);
        public string FormattedBytesReceived => FormatBytes(BytesReceived);

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB" };
            int counter = 0;
            decimal number = bytes;

            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }

            return $"{number:n1} {suffixes[counter]}";
        }

        private string FormatBits(long bits)
        {
            string[] suffixes = { "bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps" };
            int counter = 0;
            decimal number = bits;

            while (Math.Round(number / 1000) >= 1)
            {
                number /= 1000;
                counter++;
            }

            return $"{number:n1} {suffixes[counter]}";
        }
    }
}