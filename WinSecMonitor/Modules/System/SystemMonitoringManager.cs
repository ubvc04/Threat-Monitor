using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.System
{
    public class SystemMonitoringManager : IDisposable
    {
        private readonly Logger _logger;
        private readonly Dispatcher _dispatcher;
        private readonly SystemMonitor _systemMonitor;
        private readonly HardwareMonitor _hardwareMonitor;
        private readonly ApplicationMonitor _applicationMonitor;
        private readonly ProcessMonitor _processMonitor;
        
        private Timer _hardwareUpdateTimer;
        private Timer _processUpdateTimer;
        private bool _isDisposed;

        // Events for real-time updates
        public event EventHandler SystemInfoUpdated;
        public event EventHandler HardwareInfoUpdated;
        public event EventHandler ApplicationsUpdated;
        public event EventHandler ProcessesUpdated;
        public event EventHandler ServicesUpdated;

        // Properties to access the monitors
        public SystemMonitor SystemMonitor => _systemMonitor;
        public HardwareMonitor HardwareMonitor => _hardwareMonitor;
        public ApplicationMonitor ApplicationMonitor => _applicationMonitor;
        public ProcessMonitor ProcessMonitor => _processMonitor;

        public SystemMonitoringManager(Dispatcher dispatcher)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;
            
            try
            {
                _logger.LogDebug("Initializing SystemMonitoringManager");
                
                // Initialize all monitors
                _systemMonitor = new SystemMonitor();
                _hardwareMonitor = new HardwareMonitor();
                _applicationMonitor = new ApplicationMonitor();
                _processMonitor = new ProcessMonitor();
                
                _logger.LogInformation("SystemMonitoringManager initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing SystemMonitoringManager");
                throw;
            }
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogDebug("Starting initial data collection");
                
                // Collect initial system information
                _systemMonitor.RefreshSystemInfo();
                await _hardwareMonitor.RefreshHardwareInfoAsync();
                await _applicationMonitor.RefreshInstalledApplicationsAsync();
                await _processMonitor.RefreshProcessesAsync();
                await _processMonitor.RefreshServicesAsync();
                
                // Raise initial events
                OnSystemInfoUpdated();
                OnHardwareInfoUpdated();
                OnApplicationsUpdated();
                OnProcessesUpdated();
                OnServicesUpdated();
                
                _logger.LogInformation("Initial data collection completed");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error during initial data collection");
                throw;
            }
        }

        public void StartRealTimeMonitoring()
        {
            try
            {
                _logger.LogDebug("Starting real-time monitoring");
                
                // Update hardware info every 2 seconds
                _hardwareUpdateTimer = new Timer(async _ =>
                {
                    try
                    {
                        await _hardwareMonitor.RefreshHardwareInfoAsync();
                        OnHardwareInfoUpdated();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogException(ex, "Error updating hardware info");
                    }
                }, null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
                
                // Update process info every 5 seconds
                _processUpdateTimer = new Timer(async _ =>
                {
                    try
                    {
                        await _processMonitor.RefreshProcessesAsync();
                        OnProcessesUpdated();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogException(ex, "Error updating process info");
                    }
                }, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
                
                _logger.LogInformation("Real-time monitoring started");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error starting real-time monitoring");
                throw;
            }
        }

        public void StopRealTimeMonitoring()
        {
            try
            {
                _logger.LogDebug("Stopping real-time monitoring");
                
                _hardwareUpdateTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _processUpdateTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                
                _logger.LogInformation("Real-time monitoring stopped");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error stopping real-time monitoring");
            }
        }

        public async Task RefreshSystemInfoAsync()
        {
            try
            {
                _systemMonitor.RefreshSystemInfo();
                OnSystemInfoUpdated();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing system info");
            }
        }

        public async Task RefreshApplicationsAsync()
        {
            try
            {
                await _applicationMonitor.RefreshInstalledApplicationsAsync();
                OnApplicationsUpdated();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing applications");
            }
        }

        public async Task RefreshServicesAsync()
        {
            try
            {
                await _processMonitor.RefreshServicesAsync();
                OnServicesUpdated();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing services");
            }
        }

        private void OnSystemInfoUpdated()
        {
            _dispatcher.Invoke(() => SystemInfoUpdated?.Invoke(this, EventArgs.Empty));
        }

        private void OnHardwareInfoUpdated()
        {
            _dispatcher.Invoke(() => HardwareInfoUpdated?.Invoke(this, EventArgs.Empty));
        }

        private void OnApplicationsUpdated()
        {
            _dispatcher.Invoke(() => ApplicationsUpdated?.Invoke(this, EventArgs.Empty));
        }

        private void OnProcessesUpdated()
        {
            _dispatcher.Invoke(() => ProcessesUpdated?.Invoke(this, EventArgs.Empty));
        }

        private void OnServicesUpdated()
        {
            _dispatcher.Invoke(() => ServicesUpdated?.Invoke(this, EventArgs.Empty));
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
                return;

            if (disposing)
            {
                StopRealTimeMonitoring();
                _hardwareUpdateTimer?.Dispose();
                _processUpdateTimer?.Dispose();
                _logger.LogDebug("SystemMonitoringManager disposed");
            }

            _isDisposed = true;
        }
    }
}