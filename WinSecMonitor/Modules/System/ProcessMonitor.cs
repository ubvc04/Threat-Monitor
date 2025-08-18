using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Threading.Tasks;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.System
{
    public class ProcessMonitor
    {
        private readonly Logger _logger;
        public List<ProcessInfo> RunningProcesses { get; private set; }
        public List<ServiceInfo> RunningServices { get; private set; }

        public ProcessMonitor()
        {
            _logger = Logger.Instance;
            RunningProcesses = new List<ProcessInfo>();
            RunningServices = new List<ServiceInfo>();
            _logger.LogDebug("ProcessMonitor initialized");
        }

        public async Task RefreshProcessesAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing running processes list");
                await Task.Run(() => GetRunningProcesses());
                _logger.LogInformation($"Found {RunningProcesses.Count} running processes");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing running processes");
            }
        }

        public async Task RefreshServicesAsync()
        {
            try
            {
                _logger.LogDebug("Refreshing running services list");
                await Task.Run(() => GetRunningServices());
                _logger.LogInformation($"Found {RunningServices.Count} services");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing running services");
            }
        }

        private void GetRunningProcesses()
        {
            try
            {
                var processes = new List<ProcessInfo>();
                Process[] runningProcesses = Process.GetProcesses();

                foreach (Process process in runningProcesses)
                {
                    try
                    {
                        var processInfo = new ProcessInfo
                        {
                            Id = process.Id,
                            Name = process.ProcessName,
                            MemoryUsage = process.WorkingSet64,
                            StartTime = GetProcessStartTime(process),
                            ThreadCount = process.Threads.Count,
                            Priority = process.BasePriority,
                            SessionId = process.SessionId
                        };

                        // Try to get the executable path
                        try
                        {
                            processInfo.ExecutablePath = process.MainModule?.FileName ?? "Access Denied";
                        }
                        catch
                        {
                            processInfo.ExecutablePath = "Access Denied";
                        }

                        // Try to get the company name
                        try
                        {
                            processInfo.CompanyName = process.MainModule?.FileVersionInfo.CompanyName ?? "Unknown";
                        }
                        catch
                        {
                            processInfo.CompanyName = "Unknown";
                        }

                        // Try to get CPU usage using WMI
                        try
                        {
                            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                                $"SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfProc_Process WHERE IDProcess = {process.Id}"))
                            {
                                foreach (ManagementObject obj in searcher.Get())
                                {
                                    processInfo.CpuUsage = Convert.ToSingle(obj["PercentProcessorTime"]);
                                    break;
                                }
                            }
                        }
                        catch
                        {
                            processInfo.CpuUsage = 0;
                        }

                        processes.Add(processInfo);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error getting details for process {process.Id}: {ex.Message}");
                    }
                }

                RunningProcesses = processes.OrderByDescending(p => p.CpuUsage).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting running processes");
                RunningProcesses.Clear();
            }
        }

        private DateTime? GetProcessStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch
            {
                return null;
            }
        }

        private void GetRunningServices()
        {
            try
            {
                var services = new List<ServiceInfo>();
                ServiceController[] serviceControllers = ServiceController.GetServices();

                foreach (ServiceController sc in serviceControllers)
                {
                    try
                    {
                        var serviceInfo = new ServiceInfo
                        {
                            Name = sc.ServiceName,
                            DisplayName = sc.DisplayName,
                            Status = sc.Status.ToString(),
                            StartType = GetServiceStartType(sc.ServiceName),
                            AccountName = GetServiceAccountName(sc.ServiceName),
                            Description = GetServiceDescription(sc.ServiceName),
                            ProcessId = GetServiceProcessId(sc.ServiceName),
                            CanStop = sc.CanStop,
                            CanPauseAndContinue = sc.CanPauseAndContinue
                        };

                        services.Add(serviceInfo);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error getting details for service {sc.ServiceName}: {ex.Message}");
                    }
                }

                RunningServices = services.OrderBy(s => s.Name).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error getting running services");
                RunningServices.Clear();
            }
        }

        private string GetServiceStartType(string serviceName)
        {
            try
            {
                using (ManagementObject service = new ManagementObject($"Win32_Service.Name='{serviceName}'"))
                {
                    service.Get();
                    int startMode = Convert.ToInt32(service["StartMode"]);
                    switch (startMode)
                    {
                        case 0: return "Boot";
                        case 1: return "System";
                        case 2: return "Automatic";
                        case 3: return "Manual";
                        case 4: return "Disabled";
                        default: return "Unknown";
                    }
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetServiceAccountName(string serviceName)
        {
            try
            {
                using (ManagementObject service = new ManagementObject($"Win32_Service.Name='{serviceName}'"))
                {
                    service.Get();
                    return service["StartName"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetServiceDescription(string serviceName)
        {
            try
            {
                using (ManagementObject service = new ManagementObject($"Win32_Service.Name='{serviceName}'"))
                {
                    service.Get();
                    return service["Description"]?.ToString() ?? "";
                }
            }
            catch
            {
                return "";
            }
        }

        private int GetServiceProcessId(string serviceName)
        {
            try
            {
                using (ManagementObject service = new ManagementObject($"Win32_Service.Name='{serviceName}'"))
                {
                    service.Get();
                    return Convert.ToInt32(service["ProcessId"]);
                }
            }
            catch
            {
                return 0;
            }
        }
    }

    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string ExecutablePath { get; set; }
        public string CompanyName { get; set; }
        public long MemoryUsage { get; set; }
        public float CpuUsage { get; set; }
        public DateTime? StartTime { get; set; }
        public int ThreadCount { get; set; }
        public int Priority { get; set; }
        public int SessionId { get; set; }

        public string FormattedMemoryUsage => FormatBytes(MemoryUsage);
        public string FormattedStartTime => StartTime.HasValue ? StartTime.Value.ToString("g") : "Unknown";
        public string FormattedCpuUsage => $"{CpuUsage:F1}%";

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

    public class ServiceInfo
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Status { get; set; }
        public string StartType { get; set; }
        public string AccountName { get; set; }
        public string Description { get; set; }
        public int ProcessId { get; set; }
        public bool CanStop { get; set; }
        public bool CanPauseAndContinue { get; set; }
    }
}