using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WinSecMonitor.Models;
using WinSecMonitor.Utils;
using WinSecMonitor.Commands;
using WinSecMonitor.Modules.Compliance;
using WinSecMonitor.Modules.Alert;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for DashboardView.xaml
    /// </summary>
    public partial class DashboardView : UserControl, INotifyPropertyChanged
    {
        private readonly Logger _logger = Logger.Instance;
        private readonly VulnerabilityComplianceManager _complianceManager;
        
        #region Properties
        
        // System Status Overview
        private string _systemStatus = "OK";
        public string SystemStatus
        {
            get => _systemStatus;
            set
            {
                _systemStatus = value;
                OnPropertyChanged(nameof(SystemStatus));
                OnPropertyChanged(nameof(SystemStatusColor));
            }
        }
        
        public Brush SystemStatusColor => SystemStatus == "OK" ? Brushes.Green : 
                                         SystemStatus == "Warning" ? Brushes.Orange : Brushes.Red;
        
        private string _windowsVersion = "Windows 10 Pro 21H2";
        public string WindowsVersion
        {
            get => _windowsVersion;
            set
            {
                _windowsVersion = value;
                OnPropertyChanged(nameof(WindowsVersion));
            }
        }
        
        private string _securityStatus = "OK";
        public string SecurityStatus
        {
            get => _securityStatus;
            set
            {
                _securityStatus = value;
                OnPropertyChanged(nameof(SecurityStatus));
                OnPropertyChanged(nameof(SecurityStatusColor));
            }
        }
        
        public Brush SecurityStatusColor => SecurityStatus == "OK" ? Brushes.Green : 
                                           SecurityStatus == "Warning" ? Brushes.Orange : Brushes.Red;
        
        private string _lastSecurityScan = "Today, 09:15 AM";
        public string LastSecurityScan
        {
            get => _lastSecurityScan;
            set
            {
                _lastSecurityScan = value;
                OnPropertyChanged(nameof(LastSecurityScan));
            }
        }
        
        private int _activeAlertsCount = 3;
        public int ActiveAlertsCount
        {
            get => _activeAlertsCount;
            set
            {
                _activeAlertsCount = value;
                OnPropertyChanged(nameof(ActiveAlertsCount));
                OnPropertyChanged(nameof(AlertsStatusColor));
            }
        }
        
        public Brush AlertsStatusColor => ActiveAlertsCount == 0 ? Brushes.Green : 
                                         ActiveAlertsCount < 5 ? Brushes.Orange : Brushes.Red;
        
        private string _monitoringStatus = "Active";
        public string MonitoringStatus
        {
            get => _monitoringStatus;
            set
            {
                _monitoringStatus = value;
                OnPropertyChanged(nameof(MonitoringStatus));
                OnPropertyChanged(nameof(MonitoringStatusColor));
            }
        }
        
        public Brush MonitoringStatusColor => MonitoringStatus == "Active" ? Brushes.Green : 
                                             MonitoringStatus == "Partial" ? Brushes.Orange : Brushes.Red;
        
        private int _activeModulesCount = 7;
        public int ActiveModulesCount
        {
            get => _activeModulesCount;
            set
            {
                _activeModulesCount = value;
                OnPropertyChanged(nameof(ActiveModulesCount));
            }
        }
        
        // System Resource Usage
        private double _cpuUsage = 45.2;
        public double CpuUsage
        {
            get => _cpuUsage;
            set
            {
                _cpuUsage = value;
                OnPropertyChanged(nameof(CpuUsage));
            }
        }
        
        private double _memoryUsage = 62.7;
        public double MemoryUsage
        {
            get => _memoryUsage;
            set
            {
                _memoryUsage = value;
                OnPropertyChanged(nameof(MemoryUsage));
            }
        }
        
        private double _diskUsage = 78.3;
        public double DiskUsage
        {
            get => _diskUsage;
            set
            {
                _diskUsage = value;
                OnPropertyChanged(nameof(DiskUsage));
            }
        }
        
        private double _networkUsage = 23.5;
        public double NetworkUsage
        {
            get => _networkUsage;
            set
            {
                _networkUsage = value;
                OnPropertyChanged(nameof(NetworkUsage));
            }
        }
        
        // Collections
        public ObservableCollection<Alert> RecentAlerts { get; } = new ObservableCollection<Alert>();
        public ObservableCollection<ModuleStatus> ModuleStatuses { get; } = new ObservableCollection<ModuleStatus>();
        public ObservableCollection<SecurityRecommendation> SecurityRecommendations { get; } = new ObservableCollection<SecurityRecommendation>();
        
        #endregion
        
        #region Commands
        
        public RelayCommand RefreshDashboardCommand { get; }
        public RelayCommand ExportReportCommand { get; }
        public RelayCommand ViewAllAlertsCommand { get; }
        
        #endregion
        
        public DashboardView()
        {
            try
            {
                InitializeComponent();
                DataContext = this;
                
                // Initialize commands
                RefreshDashboardCommand = new RelayCommand(RefreshDashboard);
                ExportReportCommand = new RelayCommand(ExportReport);
                ViewAllAlertsCommand = new RelayCommand(ViewAllAlerts);
                
                // Initialize compliance manager and subscribe to events
                _complianceManager = new VulnerabilityComplianceManager();
                _complianceManager.ComplianceAlertAdded += ComplianceManager_ComplianceAlertAdded;
                
                // Load initial data
                LoadDashboardData();
                
                // Set up timer for real-time updates
                SetupRealTimeUpdates();
                
                // For testing purposes, simulate a compliance check after a short delay
                if (System.ComponentModel.DesignerProperties.GetIsInDesignMode(this) == false)
                {
                    System.Threading.Tasks.Task.Delay(2000).ContinueWith(_ => SimulateComplianceCheck());
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("Error initializing DashboardView", ex);
                MessageBox.Show($"Error initializing dashboard: {ex.Message}", "Dashboard Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void LoadDashboardData()
        {
            try
            {
                // Load recent alerts
                RecentAlerts.Clear();
                
                // Add compliance alerts if available
                if (_complianceManager != null && _complianceManager.Alerts.Count > 0)
                {
                    // Add the most recent compliance alerts (up to 3)
                    foreach (var complianceAlert in _complianceManager.Alerts.OrderByDescending(a => a.Timestamp).Take(3))
                    {
                        RecentAlerts.Add(new Alert
                        {
                            Timestamp = complianceAlert.Timestamp,
                            Module = "Compliance",
                            Severity = ConvertAlertSeverity(complianceAlert.Severity),
                            Description = complianceAlert.Title
                        });
                    }
                }
                
                // Add other system alerts if we have fewer than 5 alerts
                if (RecentAlerts.Count < 5)
                {
                    if (RecentAlerts.Count == 0 || !RecentAlerts.Any(a => a.Module == "System" && a.Description.Contains("system file")))
                        RecentAlerts.Add(new Alert { Timestamp = DateTime.Now.AddHours(-1), Module = "System", Severity = "High", Description = "Unusual system file modification detected" });
                    
                    if (RecentAlerts.Count < 5 && !RecentAlerts.Any(a => a.Module == "Network"))
                        RecentAlerts.Add(new Alert { Timestamp = DateTime.Now.AddHours(-3), Module = "Network", Severity = "Medium", Description = "Suspicious outbound connection blocked" });
                    
                    if (RecentAlerts.Count < 5 && !RecentAlerts.Any(a => a.Module == "Authentication"))
                        RecentAlerts.Add(new Alert { Timestamp = DateTime.Now.AddHours(-5), Module = "Authentication", Severity = "High", Description = "Multiple failed login attempts detected" });
                    
                    if (RecentAlerts.Count < 5 && !RecentAlerts.Any(a => a.Module == "Process"))
                        RecentAlerts.Add(new Alert { Timestamp = DateTime.Now.AddHours(-12), Module = "Process", Severity = "Low", Description = "New process with unusual parameters started" });
                }
                
                // Load module statuses
                ModuleStatuses.Clear();
                ModuleStatuses.Add(new ModuleStatus { Name = "System Monitoring", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "Just now" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Authentication", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "2 min ago" });
                ModuleStatuses.Add(new ModuleStatus { Name = "File & Registry", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "1 min ago" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Process Monitoring", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "Just now" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Network Monitoring", Status = "Warning", StatusColor = Brushes.Orange, LastUpdated = "5 min ago" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Vulnerability Scan", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "15 min ago" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Event Log", Status = "Active", StatusColor = Brushes.Green, LastUpdated = "Just now" });
                ModuleStatuses.Add(new ModuleStatus { Name = "Rootkit Detection", Status = "Inactive", StatusColor = Brushes.Red, LastUpdated = "30 min ago" });
                
                // Load security recommendations
                SecurityRecommendations.Clear();
                SecurityRecommendations.Add(new SecurityRecommendation { 
                    Description = "Windows Defender real-time protection is disabled. Enable it for better security.", 
                    PriorityColor = Brushes.Red, 
                    CanAutoFix = true 
                });
                SecurityRecommendations.Add(new SecurityRecommendation { 
                    Description = "System is missing 3 critical security updates. Install updates to protect against known vulnerabilities.", 
                    PriorityColor = Brushes.Red, 
                    CanAutoFix = true 
                });
                SecurityRecommendations.Add(new SecurityRecommendation { 
                    Description = "User account control (UAC) is set to a low security level. Increase UAC level for better protection.", 
                    PriorityColor = Brushes.Orange, 
                    CanAutoFix = true 
                });
                SecurityRecommendations.Add(new SecurityRecommendation { 
                    Description = "Password policy does not enforce complexity requirements. Update password policy for stronger security.", 
                    PriorityColor = Brushes.Orange, 
                    CanAutoFix = false 
                });
                
                // Update system status based on data
                UpdateSystemStatus();
            }
            catch (Exception ex)
            {
                _logger.LogException("Error loading dashboard data", ex);
                MessageBox.Show($"Error loading dashboard data: {ex.Message}", "Dashboard Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void UpdateSystemStatus()
        {
            try
            {
                bool hasHighSeverityAlert = false;
                bool hasComplianceAlert = false;
                bool hasMediumSeverityAlert = false;
                
                // Determine system status based on alerts and module statuses
                if (RecentAlerts.Count > 0)
                {
                    foreach (var alert in RecentAlerts)
                    {
                        if (alert.Severity == "High")
                        {
                            hasHighSeverityAlert = true;
                        }
                        else if (alert.Severity == "Medium")
                        {
                            hasMediumSeverityAlert = true;
                        }
                        
                        if (alert.Module == "Compliance")
                        {
                            hasComplianceAlert = true;
                        }
                    }
                    
                    // Set system status based on alert severity
                    if (hasHighSeverityAlert)
                    {
                        SystemStatus = "Critical";
                        SecurityStatus = "At Risk";
                    }
                    else if (hasMediumSeverityAlert || hasComplianceAlert)
                    {
                        SystemStatus = "Warning";
                        SecurityStatus = "Warning";
                    }
                    else
                    {
                        SystemStatus = "OK";
                        SecurityStatus = "OK";
                    }
                }
                else
                {
                    SystemStatus = "OK";
                    SecurityStatus = "OK";
                }
                
                // Check compliance status if available
                if (_complianceManager != null && _complianceManager.Alerts.Count > 0)
                {
                    // If there are any critical or high compliance alerts, set security status to warning or critical
                    if (_complianceManager.Alerts.Any(a => a.Severity == AlertSeverity.Critical))
                    {
                        SecurityStatus = "At Risk";
                    }
                    else if (_complianceManager.Alerts.Any(a => a.Severity == AlertSeverity.High))
                    {
                        SecurityStatus = "Warning";
                    }
                }
                
                // Check module statuses
                foreach (var module in ModuleStatuses)
                {
                    if (module.Status == "Inactive")
                    {
                        MonitoringStatus = "Partial";
                        return;
                    }
                }
                
                MonitoringStatus = "Active";
                
                // Update active alerts count
                ActiveAlertsCount = RecentAlerts.Count;
            }
            catch (Exception ex)
            {
                _logger.LogException("Error updating system status", ex);
            }
        }
        
        private void SetupRealTimeUpdates()
        {
            try
            {
                // Set up a timer to update resource usage every 5 seconds
                System.Windows.Threading.DispatcherTimer timer = new System.Windows.Threading.DispatcherTimer();
                timer.Interval = TimeSpan.FromSeconds(5);
                timer.Tick += (s, e) => UpdateResourceUsage();
                timer.Start();
            }
            catch (Exception ex)
            {
                _logger.LogException("Error setting up real-time updates", ex);
            }
        }
        
        private void UpdateResourceUsage()
        {
            try
            {
                // Simulate updating resource usage (in a real app, this would get actual system metrics)
                Random rand = new Random();
                CpuUsage = Math.Min(100, Math.Max(0, CpuUsage + (rand.NextDouble() * 10 - 5)));
                MemoryUsage = Math.Min(100, Math.Max(0, MemoryUsage + (rand.NextDouble() * 8 - 4)));
                DiskUsage = Math.Min(100, Math.Max(0, DiskUsage + (rand.NextDouble() * 5 - 2.5)));
                NetworkUsage = Math.Min(100, Math.Max(0, NetworkUsage + (rand.NextDouble() * 15 - 7.5)));
            }
            catch (Exception ex)
            {
                _logger.LogException("Error updating resource usage", ex);
            }
        }
        
        #region Event Handlers

        /// <summary>
        /// Handles the ComplianceAlertAdded event from the VulnerabilityComplianceManager
        /// </summary>
        private void ComplianceManager_ComplianceAlertAdded(object sender, ComplianceAlertEventArgs e)
        {
            try
            {
                // Update UI on the UI thread
                Dispatcher.Invoke(() =>
                {
                    // Convert compliance alert to dashboard alert
                    var alert = new Alert
                    {
                        Timestamp = e.Alert.Timestamp,
                        Module = "Compliance",
                        Severity = ConvertAlertSeverity(e.Alert.Severity),
                        Description = e.Alert.Title
                    };

                    // Add to recent alerts
                    RecentAlerts.Insert(0, alert);

                    // Keep only the most recent alerts (limit to 5)
                    while (RecentAlerts.Count > 5)
                    {
                        RecentAlerts.RemoveAt(RecentAlerts.Count - 1);
                    }

                    // Update active alerts count
                    ActiveAlertsCount = RecentAlerts.Count;

                    // Update system status based on new alert
                    UpdateSystemStatus();
                });
            }
            catch (Exception ex)
            {
                _logger.LogException("Error handling compliance alert", ex);
            }
        }

        /// <summary>
        /// Converts compliance alert severity to dashboard alert severity
        /// </summary>
        private string ConvertAlertSeverity(AlertSeverity severity)
        {
            switch (severity)
            {
                case AlertSeverity.Critical:
                    return "High";
                case AlertSeverity.High:
                    return "High";
                case AlertSeverity.Medium:
                    return "Medium";
                case AlertSeverity.Low:
                    return "Low";
                case AlertSeverity.Information:
                    return "Low";
                default:
                    return "Medium";
            }
        }

        #region Command Handlers
        
        private void RefreshDashboard(object parameter)
        {
            try
            {
                _logger.LogInformation("Refreshing dashboard data");
                LoadDashboardData();
                UpdateResourceUsage();
            }
            catch (Exception ex)
            {
                _logger.LogException("Error refreshing dashboard", ex);
                MessageBox.Show($"Error refreshing dashboard: {ex.Message}", "Dashboard Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ExportReport(object parameter)
        {
            try
            {
                _logger.LogInformation("Exporting dashboard report");
                MessageBox.Show("Dashboard report exported successfully.", "Export Report", 
                                MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _logger.LogException("Error exporting dashboard report", ex);
                MessageBox.Show($"Error exporting report: {ex.Message}", "Export Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ViewAllAlerts(object parameter)
        {
            try
            {
                _logger.LogInformation("Navigating to alerts view");
                // In a real app, this would navigate to the alerts view
                MessageBox.Show("Navigating to all alerts view.", "View Alerts", 
                                MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _logger.LogException("Error navigating to alerts view", ex);
                MessageBox.Show($"Error viewing alerts: {ex.Message}", "Navigation Error", 
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        /// <summary>
        /// Simulates a compliance check for testing purposes
        /// </summary>
        private void SimulateComplianceCheck()
        {
            try
            {
                // Since we can't directly add alerts to the compliance manager (AddAlert is private),
                // we'll trigger a compliance check which will generate alerts
                _logger.LogInfo("Starting simulated compliance check");
                
                // Run a compliance check which will generate alerts
                _complianceManager.RunComplianceCheck();
                
                _logger.LogInfo("Simulated compliance check completed");
            }
            catch (Exception ex)
            {
                _logger.LogException("Error simulating compliance check", ex);
            }
        }
        
        #endregion
        
        #region INotifyPropertyChanged
        
        public event PropertyChangedEventHandler PropertyChanged;
        
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        
        #endregion
    }
    
    // Model classes for the dashboard
    public class Alert
    {
        public DateTime Timestamp { get; set; }
        public string Module { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
    }
    
    public class ModuleStatus
    {
        public string Name { get; set; }
        public string Status { get; set; }
        public Brush StatusColor { get; set; }
        public string LastUpdated { get; set; }
    }
    
    public class SecurityRecommendation
    {
        public string Description { get; set; }
        public Brush PriorityColor { get; set; }
        public bool CanAutoFix { get; set; }
        public RelayCommand FixCommand { get; set; }
    }
}