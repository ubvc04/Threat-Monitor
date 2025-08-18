using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinSecMonitor.Modules.System;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.GUI.Views
{
    public partial class SystemMonitoringView : UserControl, INotifyPropertyChanged
    {
        private readonly Logger _logger;
        private readonly SystemMonitoringManager _monitoringManager;

        // Properties for binding
        private SystemMonitor _systemInfo;
        private HardwareMonitor _hardwareInfo;
        private string _ramDetails;
        private string _applicationSearchText = "";
        private string _processSearchText = "";
        private string _serviceSearchText = "";
        private ObservableCollection<ApplicationInfo> _filteredApplications;
        private ObservableCollection<ProcessInfo> _filteredProcesses;
        private ObservableCollection<ServiceInfo> _filteredServices;

        // Commands
        public ICommand RefreshSystemInfoCommand { get; }
        public ICommand RefreshApplicationsCommand { get; }
        public ICommand RefreshProcessesCommand { get; }
        public ICommand RefreshServicesCommand { get; }
        public ICommand SearchApplicationsCommand { get; }
        public ICommand SearchProcessesCommand { get; }
        public ICommand SearchServicesCommand { get; }

        public SystemMonitor SystemInfo
        {
            get => _systemInfo;
            set
            {
                _systemInfo = value;
                OnPropertyChanged();
            }
        }

        public HardwareMonitor HardwareInfo
        {
            get => _hardwareInfo;
            set
            {
                _hardwareInfo = value;
                OnPropertyChanged();
                UpdateRamDetails();
            }
        }

        public string RamDetails
        {
            get => _ramDetails;
            set
            {
                _ramDetails = value;
                OnPropertyChanged();
            }
        }

        public string ApplicationSearchText
        {
            get => _applicationSearchText;
            set
            {
                _applicationSearchText = value;
                OnPropertyChanged();
                FilterApplications();
            }
        }

        public string ProcessSearchText
        {
            get => _processSearchText;
            set
            {
                _processSearchText = value;
                OnPropertyChanged();
                FilterProcesses();
            }
        }

        public string ServiceSearchText
        {
            get => _serviceSearchText;
            set
            {
                _serviceSearchText = value;
                OnPropertyChanged();
                FilterServices();
            }
        }

        public ObservableCollection<ApplicationInfo> FilteredApplications
        {
            get => _filteredApplications;
            set
            {
                _filteredApplications = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<ProcessInfo> FilteredProcesses
        {
            get => _filteredProcesses;
            set
            {
                _filteredProcesses = value;
                OnPropertyChanged();
            }
        }

        public ObservableCollection<ServiceInfo> FilteredServices
        {
            get => _filteredServices;
            set
            {
                _filteredServices = value;
                OnPropertyChanged();
            }
        }

        public SystemMonitoringView()
        {
            InitializeComponent();
            DataContext = this;
            _logger = Logger.Instance;

            try
            {
                _logger.LogDebug("Initializing SystemMonitoringView");

                // Initialize collections
                FilteredApplications = new ObservableCollection<ApplicationInfo>();
                FilteredProcesses = new ObservableCollection<ProcessInfo>();
                FilteredServices = new ObservableCollection<ServiceInfo>();

                // Initialize commands
                RefreshSystemInfoCommand = new RelayCommand(async _ => await RefreshSystemInfoAsync());
                RefreshApplicationsCommand = new RelayCommand(async _ => await RefreshApplicationsAsync());
                RefreshProcessesCommand = new RelayCommand(async _ => await RefreshProcessesAsync());
                RefreshServicesCommand = new RelayCommand(async _ => await RefreshServicesAsync());
                SearchApplicationsCommand = new RelayCommand(_ => FilterApplications());
                SearchProcessesCommand = new RelayCommand(_ => FilterProcesses());
                SearchServicesCommand = new RelayCommand(_ => FilterServices());

                // Initialize monitoring manager
                _monitoringManager = new SystemMonitoringManager(Dispatcher);
                
                // Subscribe to events
                _monitoringManager.SystemInfoUpdated += OnSystemInfoUpdated;
                _monitoringManager.HardwareInfoUpdated += OnHardwareInfoUpdated;
                _monitoringManager.ApplicationsUpdated += OnApplicationsUpdated;
                _monitoringManager.ProcessesUpdated += OnProcessesUpdated;
                _monitoringManager.ServicesUpdated += OnServicesUpdated;

                // Initialize data
                InitializeAsync();

                _logger.LogInformation("SystemMonitoringView initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing SystemMonitoringView");
                MessageBox.Show($"Error initializing system monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void InitializeAsync()
        {
            try
            {
                await _monitoringManager.InitializeAsync();
                _monitoringManager.StartRealTimeMonitoring();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error during initialization");
                MessageBox.Show($"Error initializing monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OnSystemInfoUpdated(object sender, EventArgs e)
        {
            try
            {
                SystemInfo = _monitoringManager.SystemMonitor;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error updating system info in UI");
            }
        }

        private void OnHardwareInfoUpdated(object sender, EventArgs e)
        {
            try
            {
                HardwareInfo = _monitoringManager.HardwareMonitor;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error updating hardware info in UI");
            }
        }

        private void OnApplicationsUpdated(object sender, EventArgs e)
        {
            try
            {
                FilterApplications();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error updating applications in UI");
            }
        }

        private void OnProcessesUpdated(object sender, EventArgs e)
        {
            try
            {
                FilterProcesses();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error updating processes in UI");
            }
        }

        private void OnServicesUpdated(object sender, EventArgs e)
        {
            try
            {
                FilterServices();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error updating services in UI");
            }
        }

        private void UpdateRamDetails()
        {
            if (HardwareInfo != null)
            {
                string totalRam = FormatBytes(HardwareInfo.TotalRam);
                string availableRam = FormatBytes(HardwareInfo.AvailableRam);
                string usedRam = FormatBytes(HardwareInfo.TotalRam - HardwareInfo.AvailableRam);
                RamDetails = $"{usedRam} used of {totalRam} ({availableRam} free)";
            }
        }

        private void FilterApplications()
        {
            try
            {
                var applications = _monitoringManager.ApplicationMonitor.InstalledApplications;
                if (string.IsNullOrWhiteSpace(ApplicationSearchText))
                {
                    FilteredApplications = new ObservableCollection<ApplicationInfo>(applications);
                }
                else
                {
                    string searchText = ApplicationSearchText.ToLower();
                    FilteredApplications = new ObservableCollection<ApplicationInfo>(
                        applications.Where(a => 
                            a.Name.ToLower().Contains(searchText) || 
                            a.Publisher.ToLower().Contains(searchText) ||
                            a.Version.ToLower().Contains(searchText)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering applications");
            }
        }

        private void FilterProcesses()
        {
            try
            {
                var processes = _monitoringManager.ProcessMonitor.RunningProcesses;
                if (string.IsNullOrWhiteSpace(ProcessSearchText))
                {
                    FilteredProcesses = new ObservableCollection<ProcessInfo>(processes);
                }
                else
                {
                    string searchText = ProcessSearchText.ToLower();
                    FilteredProcesses = new ObservableCollection<ProcessInfo>(
                        processes.Where(p => 
                            p.Name.ToLower().Contains(searchText) || 
                            p.CompanyName.ToLower().Contains(searchText) ||
                            p.ExecutablePath.ToLower().Contains(searchText)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering processes");
            }
        }

        private void FilterServices()
        {
            try
            {
                var services = _monitoringManager.ProcessMonitor.RunningServices;
                if (string.IsNullOrWhiteSpace(ServiceSearchText))
                {
                    FilteredServices = new ObservableCollection<ServiceInfo>(services);
                }
                else
                {
                    string searchText = ServiceSearchText.ToLower();
                    FilteredServices = new ObservableCollection<ServiceInfo>(
                        services.Where(s => 
                            s.Name.ToLower().Contains(searchText) || 
                            s.DisplayName.ToLower().Contains(searchText) ||
                            s.Description.ToLower().Contains(searchText)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering services");
            }
        }

        private async Task RefreshSystemInfoAsync()
        {
            try
            {
                await _monitoringManager.RefreshSystemInfoAsync();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing system info");
                MessageBox.Show($"Error refreshing system info: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task RefreshApplicationsAsync()
        {
            try
            {
                await _monitoringManager.RefreshApplicationsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing applications");
                MessageBox.Show($"Error refreshing applications: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task RefreshProcessesAsync()
        {
            try
            {
                await _monitoringManager.ProcessMonitor.RefreshProcessesAsync();
                FilterProcesses();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing processes");
                MessageBox.Show($"Error refreshing processes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task RefreshServicesAsync()
        {
            try
            {
                await _monitoringManager.RefreshServicesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing services");
                MessageBox.Show($"Error refreshing services: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

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

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    // Simple implementation of ICommand for the view
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;

        public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => _canExecute == null || _canExecute(parameter);

        public void Execute(object parameter) => _execute(parameter);

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}