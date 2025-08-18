using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using WinSecMonitor.Modules.EventLog;
using WinSecMonitor.Utils;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for EventLogCorrelationView.xaml
    /// </summary>
    public partial class EventLogCorrelationView : UserControl, INotifyPropertyChanged
    {
        private EventLogManager _eventLogManager;
        private ObservableCollection<EventLogEntry> _filteredEventLogs;
        private ObservableCollection<CorrelationAlert> _filteredCorrelationAlerts;
        private ObservableCollection<RootkitDetection> _filteredRootkitDetections;
        private string _logFilter;
        private string _alertFilter;
        private string _rootkitFilter;
        private string _threatIntelligenceSearch;
        private string _newLogSource;
        private string _exportPath;
        private bool _autoStartMonitoring;
        private int _collectionIntervalSeconds;
        private bool _enableRootkitDetection;
        private int _scanIntervalMinutes;
        private bool _scanHiddenProcesses;
        private bool _scanHiddenFiles;
        private bool _scanHiddenRegistry;
        private bool _scanSSDTHooks;
        private bool _scanKernelHooks;
        private string _selectedLogSource;
        private string _selectedAlertSeverity;
        private string _selectedThreatFeedType;
        private string _selectedRootkitDetectionType;
        private CorrelationAlert _selectedCorrelationAlert;
        private RootkitDetection _selectedRootkitDetection;
        private ThreatFeed _selectedThreatFeed;
        private CorrelationRule _selectedCorrelationRule;

        public EventLogCorrelationView()
        {
            InitializeComponent();
            DataContext = this;

            // Initialize collections
            FilteredEventLogs = new ObservableCollection<EventLogEntry>();
            FilteredCorrelationAlerts = new ObservableCollection<CorrelationAlert>();
            FilteredRootkitDetections = new ObservableCollection<RootkitDetection>();
            RecentAlerts = new ObservableCollection<CorrelationAlert>();
            MaliciousIPs = new ObservableCollection<dynamic>();
            MalwareHashes = new ObservableCollection<dynamic>();
            CVEs = new ObservableCollection<dynamic>();
            ThreatFeeds = new ObservableCollection<ThreatFeed>();
            CorrelationRules = new ObservableCollection<CorrelationRule>();
            ConfiguredLogSources = new ObservableCollection<string>();

            // Initialize properties
            LogSources = new List<string> { "Security", "System", "Application", "All" };
            AlertSeverities = new List<string> { "All", "Low", "Medium", "High", "Critical" };
            ThreatFeedTypes = new List<string> { "All", "MaliciousIP", "MalwareHash", "CVE" };
            RootkitDetectionTypes = new List<string> { "All", "Process", "File", "Registry", "SSDT", "Kernel" };

            // Set default values
            SelectedLogSource = "All";
            SelectedAlertSeverity = "All";
            SelectedThreatFeedType = "All";
            SelectedRootkitDetectionType = "All";
            ExportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WinSecMonitor");
            CollectionIntervalSeconds = 60;
            ScanIntervalMinutes = 60;
            ScanHiddenProcesses = true;
            ScanHiddenFiles = true;
            ScanHiddenRegistry = true;
            AutoStartMonitoring = false;
            EnableRootkitDetection = true;

            // Initialize commands
            StartCommand = new RelayCommand(StartMonitoring, CanStartMonitoring);
            StopCommand = new RelayCommand(StopMonitoring, CanStopMonitoring);
            RefreshCommand = new RelayCommand(RefreshData);
            OpenSettingsCommand = new RelayCommand(() => { /* Navigate to settings tab */ });
            ExportLogsCommand = new RelayCommand(ExportLogs);
            ApplyLogFilterCommand = new RelayCommand(ApplyLogFilter);
            ClearLogFilterCommand = new RelayCommand(ClearLogFilter);
            RefreshLogsCommand = new RelayCommand(RefreshLogs);
            ApplyAlertFilterCommand = new RelayCommand(ApplyAlertFilter);
            ClearAlertFilterCommand = new RelayCommand(ClearAlertFilter);
            ExportAlertsCommand = new RelayCommand(ExportAlerts);
            SearchThreatIntelligenceCommand = new RelayCommand(SearchThreatIntelligence);
            ClearThreatIntelligenceSearchCommand = new RelayCommand(ClearThreatIntelligenceSearch);
            UpdateThreatFeedsCommand = new RelayCommand(UpdateThreatFeeds);
            AddThreatFeedCommand = new RelayCommand(AddThreatFeed);
            UpdateSelectedFeedCommand = new RelayCommand(UpdateSelectedFeed, CanUpdateSelectedFeed);
            RemoveThreatFeedCommand = new RelayCommand(RemoveThreatFeed, CanRemoveThreatFeed);
            ScanForRootkitsCommand = new RelayCommand(ScanForRootkits);
            ApplyRootkitFilterCommand = new RelayCommand(ApplyRootkitFilter);
            ClearRootkitFilterCommand = new RelayCommand(ClearRootkitFilter);
            ExportRootkitResultsCommand = new RelayCommand(ExportRootkitResults);
            BrowseExportPathCommand = new RelayCommand(BrowseExportPath);
            AddLogSourceCommand = new RelayCommand(AddLogSource);
            RemoveLogSourceCommand = new RelayCommand(RemoveLogSource, CanRemoveLogSource);
            AddCustomLogSourceCommand = new RelayCommand(AddCustomLogSource, CanAddCustomLogSource);
            AddCorrelationRuleCommand = new RelayCommand(AddCorrelationRule);
            EditCorrelationRuleCommand = new RelayCommand(EditCorrelationRule, CanEditCorrelationRule);
            RemoveCorrelationRuleCommand = new RelayCommand(RemoveCorrelationRule, CanRemoveCorrelationRule);
            EditThreatFeedCommand = new RelayCommand(EditThreatFeed, CanEditThreatFeed);
            SaveSettingsCommand = new RelayCommand(SaveSettings);

            // Initialize EventLogManager
            try
            {   
                _eventLogManager = new EventLogManager();
                SubscribeToEvents();
                LoadSettings();
                
                if (AutoStartMonitoring)
                {
                    StartMonitoring();
                }
            }
            catch (Exception ex)
            {   
                Logger.LogError($"Error initializing EventLogCorrelationView: {ex.Message}");
                MessageBox.Show($"Error initializing Event Log module: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #region Properties

        public ObservableCollection<EventLogEntry> FilteredEventLogs
        {
            get { return _filteredEventLogs; }
            set
            {
                _filteredEventLogs = value;
                OnPropertyChanged(nameof(FilteredEventLogs));
            }
        }

        public ObservableCollection<CorrelationAlert> FilteredCorrelationAlerts
        {
            get { return _filteredCorrelationAlerts; }
            set
            {
                _filteredCorrelationAlerts = value;
                OnPropertyChanged(nameof(FilteredCorrelationAlerts));
            }
        }

        public ObservableCollection<RootkitDetection> FilteredRootkitDetections
        {
            get { return _filteredRootkitDetections; }
            set
            {
                _filteredRootkitDetections = value;
                OnPropertyChanged(nameof(FilteredRootkitDetections));
            }
        }

        public ObservableCollection<CorrelationAlert> RecentAlerts { get; set; }
        public ObservableCollection<dynamic> MaliciousIPs { get; set; }
        public ObservableCollection<dynamic> MalwareHashes { get; set; }
        public ObservableCollection<dynamic> CVEs { get; set; }
        public ObservableCollection<ThreatFeed> ThreatFeeds { get; set; }
        public ObservableCollection<CorrelationRule> CorrelationRules { get; set; }
        public ObservableCollection<string> ConfiguredLogSources { get; set; }

        public List<string> LogSources { get; set; }
        public List<string> AlertSeverities { get; set; }
        public List<string> ThreatFeedTypes { get; set; }
        public List<string> RootkitDetectionTypes { get; set; }

        public string LogFilter
        {
            get { return _logFilter; }
            set
            {
                _logFilter = value;
                OnPropertyChanged(nameof(LogFilter));
            }
        }

        public string AlertFilter
        {
            get { return _alertFilter; }
            set
            {
                _alertFilter = value;
                OnPropertyChanged(nameof(AlertFilter));
            }
        }

        public string RootkitFilter
        {
            get { return _rootkitFilter; }
            set
            {
                _rootkitFilter = value;
                OnPropertyChanged(nameof(RootkitFilter));
            }
        }

        public string ThreatIntelligenceSearch
        {
            get { return _threatIntelligenceSearch; }
            set
            {
                _threatIntelligenceSearch = value;
                OnPropertyChanged(nameof(ThreatIntelligenceSearch));
            }
        }

        public string NewLogSource
        {
            get { return _newLogSource; }
            set
            {
                _newLogSource = value;
                OnPropertyChanged(nameof(NewLogSource));
            }
        }

        public string ExportPath
        {
            get { return _exportPath; }
            set
            {
                _exportPath = value;
                OnPropertyChanged(nameof(ExportPath));
            }
        }

        public bool AutoStartMonitoring
        {
            get { return _autoStartMonitoring; }
            set
            {
                _autoStartMonitoring = value;
                OnPropertyChanged(nameof(AutoStartMonitoring));
            }
        }

        public int CollectionIntervalSeconds
        {
            get { return _collectionIntervalSeconds; }
            set
            {
                _collectionIntervalSeconds = value;
                OnPropertyChanged(nameof(CollectionIntervalSeconds));
            }
        }

        public bool EnableRootkitDetection
        {
            get { return _enableRootkitDetection; }
            set
            {
                _enableRootkitDetection = value;
                OnPropertyChanged(nameof(EnableRootkitDetection));
                OnPropertyChanged(nameof(IsRootkitDetectionEnabled));
            }
        }

        public int ScanIntervalMinutes
        {
            get { return _scanIntervalMinutes; }
            set
            {
                _scanIntervalMinutes = value;
                OnPropertyChanged(nameof(ScanIntervalMinutes));
            }
        }

        public bool ScanHiddenProcesses
        {
            get { return _scanHiddenProcesses; }
            set
            {
                _scanHiddenProcesses = value;
                OnPropertyChanged(nameof(ScanHiddenProcesses));
            }
        }

        public bool ScanHiddenFiles
        {
            get { return _scanHiddenFiles; }
            set
            {
                _scanHiddenFiles = value;
                OnPropertyChanged(nameof(ScanHiddenFiles));
            }
        }

        public bool ScanHiddenRegistry
        {
            get { return _scanHiddenRegistry; }
            set
            {
                _scanHiddenRegistry = value;
                OnPropertyChanged(nameof(ScanHiddenRegistry));
            }
        }

        public bool ScanSSDTHooks
        {
            get { return _scanSSDTHooks; }
            set
            {
                _scanSSDTHooks = value;
                OnPropertyChanged(nameof(ScanSSDTHooks));
            }
        }

        public bool ScanKernelHooks
        {
            get { return _scanKernelHooks; }
            set
            {
                _scanKernelHooks = value;
                OnPropertyChanged(nameof(ScanKernelHooks));
            }
        }

        public string SelectedLogSource
        {
            get { return _selectedLogSource; }
            set
            {
                _selectedLogSource = value;
                OnPropertyChanged(nameof(SelectedLogSource));
                ApplyLogFilter();
            }
        }

        public string SelectedAlertSeverity
        {
            get { return _selectedAlertSeverity; }
            set
            {
                _selectedAlertSeverity = value;
                OnPropertyChanged(nameof(SelectedAlertSeverity));
                ApplyAlertFilter();
            }
        }

        public string SelectedThreatFeedType
        {
            get { return _selectedThreatFeedType; }
            set
            {
                _selectedThreatFeedType = value;
                OnPropertyChanged(nameof(SelectedThreatFeedType));
                OnPropertyChanged(nameof(IsMaliciousIPsVisible));
                OnPropertyChanged(nameof(IsMalwareHashesVisible));
                OnPropertyChanged(nameof(IsCVEsVisible));
                SearchThreatIntelligence();
            }
        }

        public string SelectedRootkitDetectionType
        {
            get { return _selectedRootkitDetectionType; }
            set
            {
                _selectedRootkitDetectionType = value;
                OnPropertyChanged(nameof(SelectedRootkitDetectionType));
                ApplyRootkitFilter();
            }
        }

        public CorrelationAlert SelectedCorrelationAlert
        {
            get { return _selectedCorrelationAlert; }
            set
            {
                _selectedCorrelationAlert = value;
                OnPropertyChanged(nameof(SelectedCorrelationAlert));
            }
        }

        public RootkitDetection SelectedRootkitDetection
        {
            get { return _selectedRootkitDetection; }
            set
            {
                _selectedRootkitDetection = value;
                OnPropertyChanged(nameof(SelectedRootkitDetection));
            }
        }

        public ThreatFeed SelectedThreatFeed
        {
            get { return _selectedThreatFeed; }
            set
            {
                _selectedThreatFeed = value;
                OnPropertyChanged(nameof(SelectedThreatFeed));
            }
        }

        public CorrelationRule SelectedCorrelationRule
        {
            get { return _selectedCorrelationRule; }
            set
            {
                _selectedCorrelationRule = value;
                OnPropertyChanged(nameof(SelectedCorrelationRule));
            }
        }

        public bool IsCollectionActive => _eventLogManager?.IsCollectorRunning ?? false;
        public bool IsCorrelationActive => _eventLogManager?.IsCorrelationEngineRunning ?? false;
        public bool IsRootkitDetectionActive => _eventLogManager?.IsRootkitDetectorRunning ?? false;
        public bool IsRootkitDetectionEnabled => EnableRootkitDetection;

        public int LogSourcesCount => _eventLogManager?.EventLogCollector?.LogSources?.Count ?? 0;
        public int CollectedEntriesCount => _eventLogManager?.EventLogCollector?.CollectedEntries?.Count ?? 0;
        public DateTime? LastCollectionTime => _eventLogManager?.EventLogCollector?.LastCollectionTime;

        public int ActiveRulesCount => _eventLogManager?.EventCorrelationEngine?.ActiveRules?.Count ?? 0;
        public int AlertsCount => _eventLogManager?.EventCorrelationEngine?.Alerts?.Count ?? 0;
        public int ThreatFeedsCount => _eventLogManager?.ThreatIntelligenceManager?.ConfiguredFeeds?.Count ?? 0;

        public int RootkitDetectionsCount => _eventLogManager?.RootkitDetector?.DetectionCount ?? 0;
        public DateTime? LastRootkitScanTime => _eventLogManager?.RootkitDetector?.LastScanTime;

        public bool IsMaliciousIPsVisible => SelectedThreatFeedType == "All" || SelectedThreatFeedType == "MaliciousIP";
        public bool IsMalwareHashesVisible => SelectedThreatFeedType == "All" || SelectedThreatFeedType == "MalwareHash";
        public bool IsCVEsVisible => SelectedThreatFeedType == "All" || SelectedThreatFeedType == "CVE";

        #endregion

        #region Commands

        public ICommand StartCommand { get; private set; }
        public ICommand StopCommand { get; private set; }
        public ICommand RefreshCommand { get; private set; }
        public ICommand OpenSettingsCommand { get; private set; }
        public ICommand ExportLogsCommand { get; private set; }
        public ICommand ApplyLogFilterCommand { get; private set; }
        public ICommand ClearLogFilterCommand { get; private set; }
        public ICommand RefreshLogsCommand { get; private set; }
        public ICommand ApplyAlertFilterCommand { get; private set; }
        public ICommand ClearAlertFilterCommand { get; private set; }
        public ICommand ExportAlertsCommand { get; private set; }
        public ICommand SearchThreatIntelligenceCommand { get; private set; }
        public ICommand ClearThreatIntelligenceSearchCommand { get; private set; }
        public ICommand UpdateThreatFeedsCommand { get; private set; }
        public ICommand AddThreatFeedCommand { get; private set; }
        public ICommand UpdateSelectedFeedCommand { get; private set; }
        public ICommand RemoveThreatFeedCommand { get; private set; }
        public ICommand ScanForRootkitsCommand { get; private set; }
        public ICommand ApplyRootkitFilterCommand { get; private set; }
        public ICommand ClearRootkitFilterCommand { get; private set; }
        public ICommand ExportRootkitResultsCommand { get; private set; }
        public ICommand BrowseExportPathCommand { get; private set; }
        public ICommand AddLogSourceCommand { get; private set; }
        public ICommand RemoveLogSourceCommand { get; private set; }
        public ICommand AddCustomLogSourceCommand { get; private set; }
        public ICommand AddCorrelationRuleCommand { get; private set; }
        public ICommand EditCorrelationRuleCommand { get; private set; }
        public ICommand RemoveCorrelationRuleCommand { get; private set; }
        public ICommand EditThreatFeedCommand { get; private set; }
        public ICommand SaveSettingsCommand { get; private set; }

        #endregion

        #region Command Handlers

        private void StartMonitoring()
        {
            try
            {   
                _eventLogManager.StartAll();
                RefreshData();
                UpdateStatusProperties();
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error starting monitoring: {ex.Message}");
                MessageBox.Show($"Error starting monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanStartMonitoring()
        {
            return _eventLogManager != null && !IsCollectionActive;
        }

        private void StopMonitoring()
        {
            try
            {   
                _eventLogManager.StopAll();
                UpdateStatusProperties();
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error stopping monitoring: {ex.Message}");
                MessageBox.Show($"Error stopping monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanStopMonitoring()
        {
            return _eventLogManager != null && IsCollectionActive;
        }

        private void RefreshData()
        {
            RefreshLogs();
            RefreshAlerts();
            RefreshRootkitDetections();
            RefreshThreatIntelligence();
            UpdateStatusProperties();
        }

        private void ExportLogs()
        {
            try
            {   
                if (!Directory.Exists(ExportPath))
                {
                    Directory.CreateDirectory(ExportPath);
                }

                string fileName = Path.Combine(ExportPath, $"EventLogs_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                using (StreamWriter writer = new StreamWriter(fileName))
                {
                    writer.WriteLine("Timestamp,Source,EventId,Level,Message");
                    foreach (var entry in FilteredEventLogs)
                    {
                        writer.WriteLine($"\"{entry.Timestamp}\",\"{entry.Source}\",{entry.EventId},\"{entry.Level}\",\"{entry.Message.Replace("\"", "\"\"")}\"";
                    }
                }

                MessageBox.Show($"Event logs exported to {fileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error exporting logs: {ex.Message}");
                MessageBox.Show($"Error exporting logs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyLogFilter()
        {
            try
            {   
                if (_eventLogManager?.EventLogCollector?.CollectedEntries == null)
                    return;

                var entries = _eventLogManager.EventLogCollector.CollectedEntries.AsEnumerable();

                // Filter by source
                if (!string.IsNullOrEmpty(SelectedLogSource) && SelectedLogSource != "All")
                {
                    entries = entries.Where(e => e.Source == SelectedLogSource);
                }

                // Filter by text
                if (!string.IsNullOrEmpty(LogFilter))
                {
                    entries = entries.Where(e => 
                        e.Message.IndexOf(LogFilter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        e.Source.IndexOf(LogFilter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        e.EventId.ToString().Contains(LogFilter));
                }

                // Update collection
                FilteredEventLogs.Clear();
                foreach (var entry in entries.Take(1000)) // Limit to 1000 entries for performance
                {
                    FilteredEventLogs.Add(entry);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error applying log filter: {ex.Message}");
            }
        }

        private void ClearLogFilter()
        {
            LogFilter = string.Empty;
            SelectedLogSource = "All";
            ApplyLogFilter();
        }

        private void RefreshLogs()
        {
            try
            {   
                if (_eventLogManager?.EventLogCollector != null)
                {
                    ApplyLogFilter();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error refreshing logs: {ex.Message}");
            }
        }

        private void ApplyAlertFilter()
        {
            try
            {   
                if (_eventLogManager?.EventCorrelationEngine?.Alerts == null)
                    return;

                var alerts = _eventLogManager.EventCorrelationEngine.Alerts.AsEnumerable();

                // Filter by severity
                if (!string.IsNullOrEmpty(SelectedAlertSeverity) && SelectedAlertSeverity != "All")
                {
                    AlertSeverity severity = (AlertSeverity)Enum.Parse(typeof(AlertSeverity), SelectedAlertSeverity);
                    alerts = alerts.Where(a => a.Severity == severity);
                }

                // Filter by text
                if (!string.IsNullOrEmpty(AlertFilter))
                {
                    alerts = alerts.Where(a => 
                        a.Description.IndexOf(AlertFilter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        a.RuleName.IndexOf(AlertFilter, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                // Update collection
                FilteredCorrelationAlerts.Clear();
                foreach (var alert in alerts)
                {
                    FilteredCorrelationAlerts.Add(alert);
                }

                // Update recent alerts
                RecentAlerts.Clear();
                foreach (var alert in alerts.OrderByDescending(a => a.Timestamp).Take(10))
                {
                    RecentAlerts.Add(alert);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error applying alert filter: {ex.Message}");
            }
        }

        private void ClearAlertFilter()
        {
            AlertFilter = string.Empty;
            SelectedAlertSeverity = "All";
            ApplyAlertFilter();
        }

        private void RefreshAlerts()
        {
            try
            {   
                if (_eventLogManager?.EventCorrelationEngine != null)
                {
                    ApplyAlertFilter();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error refreshing alerts: {ex.Message}");
            }
        }

        private void ExportAlerts()
        {
            try
            {   
                if (!Directory.Exists(ExportPath))
                {
                    Directory.CreateDirectory(ExportPath);
                }

                string fileName = Path.Combine(ExportPath, $"CorrelationAlerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                using (StreamWriter writer = new StreamWriter(fileName))
                {
                    writer.WriteLine("Timestamp,Rule,Severity,Description");
                    foreach (var alert in FilteredCorrelationAlerts)
                    {
                        writer.WriteLine($"\"{alert.Timestamp}\",\"{alert.RuleName}\",\"{alert.Severity}\",\"{alert.Description.Replace("\"", "\"\"")}\"";
                    }
                }

                MessageBox.Show($"Correlation alerts exported to {fileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error exporting alerts: {ex.Message}");
                MessageBox.Show($"Error exporting alerts: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SearchThreatIntelligence()
        {
            try
            {   
                if (_eventLogManager?.ThreatIntelligenceManager == null)
                    return;

                // Clear existing data
                MaliciousIPs.Clear();
                MalwareHashes.Clear();
                CVEs.Clear();

                // Apply search based on selected feed type
                if (SelectedThreatFeedType == "All" || SelectedThreatFeedType == "MaliciousIP")
                {
                    var ips = _eventLogManager.ThreatIntelligenceManager.GetAllMaliciousIPs();
                    if (!string.IsNullOrEmpty(ThreatIntelligenceSearch))
                    {
                        ips = ips.Where(ip => 
                            ip.IPAddress.Contains(ThreatIntelligenceSearch) ||
                            (ip.Description != null && ip.Description.IndexOf(ThreatIntelligenceSearch, StringComparison.OrdinalIgnoreCase) >= 0) ||
                            (ip.Category != null && ip.Category.IndexOf(ThreatIntelligenceSearch, StringComparison.OrdinalIgnoreCase) >= 0));
                    }

                    foreach (var ip in ips)
                    {
                        MaliciousIPs.Add(ip);
                    }
                }

                if (SelectedThreatFeedType == "All" || SelectedThreatFeedType == "MalwareHash")
                {
                    var hashes = _eventLogManager.ThreatIntelligenceManager.GetAllMalwareHashes();
                    if (!string.IsNullOrEmpty(ThreatIntelligenceSearch))
                    {
                        hashes = hashes.Where(h => 
                            h.Hash.Contains(ThreatIntelligenceSearch) ||
                            (h.MalwareName != null && h.MalwareName.IndexOf(ThreatIntelligenceSearch, StringComparison.OrdinalIgnoreCase) >= 0));
                    }

                    foreach (var hash in hashes)
                    {
                        MalwareHashes.Add(hash);
                    }
                }

                if (SelectedThreatFeedType == "All" || SelectedThreatFeedType == "CVE")
                {
                    var cves = _eventLogManager.ThreatIntelligenceManager.GetAllCVEs();
                    if (!string.IsNullOrEmpty(ThreatIntelligenceSearch))
                    {
                        cves = cves.Where(c => 
                            c.CveId.Contains(ThreatIntelligenceSearch) ||
                            (c.Description != null && c.Description.IndexOf(ThreatIntelligenceSearch, StringComparison.OrdinalIgnoreCase) >= 0));
                    }

                    foreach (var cve in cves)
                    {
                        CVEs.Add(cve);
                    }
                }

                // Update feed list
                ThreatFeeds.Clear();
                foreach (var feed in _eventLogManager.ThreatIntelligenceManager.ConfiguredFeeds)
                {
                    ThreatFeeds.Add(feed);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error searching threat intelligence: {ex.Message}");
            }
        }

        private void ClearThreatIntelligenceSearch()
        {
            ThreatIntelligenceSearch = string.Empty;
            SearchThreatIntelligence();
        }

        private void RefreshThreatIntelligence()
        {
            SearchThreatIntelligence();
        }

        private void UpdateThreatFeeds()
        {
            try
            {   
                _eventLogManager.UpdateThreatIntelligence();
                MessageBox.Show("Threat intelligence update started. This may take a few minutes.", "Update Started", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error updating threat feeds: {ex.Message}");
                MessageBox.Show($"Error updating threat feeds: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddThreatFeed()
        {
            // This would typically open a dialog to add a new feed
            // For now, we'll just show a placeholder message
            MessageBox.Show("This would open a dialog to add a new threat feed.", "Add Threat Feed", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void UpdateSelectedFeed()
        {
            try
            {   
                if (SelectedThreatFeed != null)
                {
                    _eventLogManager.ThreatIntelligenceManager.UpdateFeed(SelectedThreatFeed);
                    MessageBox.Show($"Update of feed '{SelectedThreatFeed.Name}' started.", "Update Started", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error updating selected feed: {ex.Message}");
                MessageBox.Show($"Error updating selected feed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanUpdateSelectedFeed()
        {
            return SelectedThreatFeed != null;
        }

        private void RemoveThreatFeed()
        {
            try
            {   
                if (SelectedThreatFeed != null)
                {
                    if (MessageBox.Show($"Are you sure you want to remove the feed '{SelectedThreatFeed.Name}'?", "Confirm Removal", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    {
                        _eventLogManager.ThreatIntelligenceManager.RemoveFeed(SelectedThreatFeed);
                        ThreatFeeds.Remove(SelectedThreatFeed);
                        MessageBox.Show("Feed removed successfully.", "Feed Removed", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error removing threat feed: {ex.Message}");
                MessageBox.Show($"Error removing threat feed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanRemoveThreatFeed()
        {
            return SelectedThreatFeed != null;
        }

        private void ScanForRootkits()
        {
            try
            {   
                if (_eventLogManager?.RootkitDetector != null)
                {
                    _eventLogManager.ScanForRootkits();
                    MessageBox.Show("Rootkit scan started. This may take a few minutes.", "Scan Started", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error starting rootkit scan: {ex.Message}");
                MessageBox.Show($"Error starting rootkit scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyRootkitFilter()
        {
            try
            {   
                if (_eventLogManager?.RootkitDetector?.Detections == null)
                    return;

                var detections = _eventLogManager.RootkitDetector.Detections.AsEnumerable();

                // Filter by type
                if (!string.IsNullOrEmpty(SelectedRootkitDetectionType) && SelectedRootkitDetectionType != "All")
                {
                    RootkitDetectionType type = (RootkitDetectionType)Enum.Parse(typeof(RootkitDetectionType), SelectedRootkitDetectionType);
                    detections = detections.Where(d => d.Type == type);
                }

                // Filter by text
                if (!string.IsNullOrEmpty(RootkitFilter))
                {
                    detections = detections.Where(d => 
                        d.Description.IndexOf(RootkitFilter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        d.Location.IndexOf(RootkitFilter, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                // Update collection
                FilteredRootkitDetections.Clear();
                foreach (var detection in detections)
                {
                    FilteredRootkitDetections.Add(detection);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error applying rootkit filter: {ex.Message}");
            }
        }

        private void ClearRootkitFilter()
        {
            RootkitFilter = string.Empty;
            SelectedRootkitDetectionType = "All";
            ApplyRootkitFilter();
        }

        private void RefreshRootkitDetections()
        {
            try
            {   
                if (_eventLogManager?.RootkitDetector != null)
                {
                    ApplyRootkitFilter();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error refreshing rootkit detections: {ex.Message}");
            }
        }

        private void ExportRootkitResults()
        {
            try
            {   
                if (!Directory.Exists(ExportPath))
                {
                    Directory.CreateDirectory(ExportPath);
                }

                string fileName = Path.Combine(ExportPath, $"RootkitDetections_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                using (StreamWriter writer = new StreamWriter(fileName))
                {
                    writer.WriteLine("DetectionTime,Type,Severity,Location,Description");
                    foreach (var detection in FilteredRootkitDetections)
                    {
                        writer.WriteLine($"\"{detection.DetectionTime}\",\"{detection.Type}\",\"{detection.Severity}\",\"{detection.Location}\",\"{detection.Description.Replace("\"", "\"\"")}\"";
                    }
                }

                MessageBox.Show($"Rootkit detections exported to {fileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error exporting rootkit results: {ex.Message}");
                MessageBox.Show($"Error exporting rootkit results: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BrowseExportPath()
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            dialog.SelectedPath = ExportPath;
            dialog.Description = "Select Export Directory";
            
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                ExportPath = dialog.SelectedPath;
            }
        }

        private void AddLogSource()
        {
            // This would typically open a dialog to select from available log sources
            // For now, we'll just show a placeholder message
            MessageBox.Show("This would open a dialog to select from available log sources.", "Add Log Source", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void RemoveLogSource()
        {
            // Implementation would remove selected log sources from the ConfiguredLogSources collection
            MessageBox.Show("This would remove the selected log sources.", "Remove Log Source", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private bool CanRemoveLogSource()
        {
            // Check if any log sources are selected
            return true; // Placeholder
        }

        private void AddCustomLogSource()
        {
            try
            {   
                if (!string.IsNullOrWhiteSpace(NewLogSource))
                {
                    if (_eventLogManager?.EventLogCollector != null)
                    {
                        _eventLogManager.EventLogCollector.AddLogSource(NewLogSource);
                        ConfiguredLogSources.Add(NewLogSource);
                        NewLogSource = string.Empty;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error adding custom log source: {ex.Message}");
                MessageBox.Show($"Error adding custom log source: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanAddCustomLogSource()
        {
            return !string.IsNullOrWhiteSpace(NewLogSource);
        }

        private void AddCorrelationRule()
        {
            // This would typically open a dialog to add a new correlation rule
            // For now, we'll just show a placeholder message
            MessageBox.Show("This would open a dialog to add a new correlation rule.", "Add Correlation Rule", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void EditCorrelationRule()
        {
            // This would typically open a dialog to edit the selected correlation rule
            // For now, we'll just show a placeholder message
            MessageBox.Show($"This would open a dialog to edit the rule '{SelectedCorrelationRule.Name}'.", "Edit Correlation Rule", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private bool CanEditCorrelationRule()
        {
            return SelectedCorrelationRule != null;
        }

        private void RemoveCorrelationRule()
        {
            try
            {   
                if (SelectedCorrelationRule != null)
                {
                    if (MessageBox.Show($"Are you sure you want to remove the rule '{SelectedCorrelationRule.Name}'?", "Confirm Removal", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    {
                        _eventLogManager.EventCorrelationEngine.RemoveRule(SelectedCorrelationRule);
                        CorrelationRules.Remove(SelectedCorrelationRule);
                        MessageBox.Show("Rule removed successfully.", "Rule Removed", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error removing correlation rule: {ex.Message}");
                MessageBox.Show($"Error removing correlation rule: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanRemoveCorrelationRule()
        {
            return SelectedCorrelationRule != null;
        }

        private void EditThreatFeed()
        {
            // This would typically open a dialog to edit the selected threat feed
            // For now, we'll just show a placeholder message
            MessageBox.Show($"This would open a dialog to edit the feed '{SelectedThreatFeed.Name}'.", "Edit Threat Feed", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private bool CanEditThreatFeed()
        {
            return SelectedThreatFeed != null;
        }

        private void SaveSettings()
        {
            try
            {   
                // Apply settings to the EventLogManager
                if (_eventLogManager != null)
                {
                    if (_eventLogManager.EventLogCollector != null)
                    {
                        _eventLogManager.EventLogCollector.CollectionInterval = TimeSpan.FromSeconds(CollectionIntervalSeconds);
                    }

                    if (_eventLogManager.RootkitDetector != null)
                    {
                        _eventLogManager.RootkitDetector.ScanInterval = TimeSpan.FromMinutes(ScanIntervalMinutes);
                        // Apply other rootkit settings
                    }

                    // Save settings to configuration
                    // This would typically save to app.config or a custom settings file
                }

                MessageBox.Show("Settings saved successfully.", "Settings Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error saving settings: {ex.Message}");
                MessageBox.Show($"Error saving settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region Event Handlers

        private void SubscribeToEvents()
        {
            if (_eventLogManager != null)
            {
                // EventLogCollector events
                if (_eventLogManager.EventLogCollector != null)
                {
                    _eventLogManager.EventLogCollector.EventLogEntriesCollected += EventLogCollector_EventLogEntriesCollected;
                    _eventLogManager.EventLogCollector.EventLogCollectionError += EventLogCollector_EventLogCollectionError;
                }

                // EventCorrelationEngine events
                if (_eventLogManager.EventCorrelationEngine != null)
                {
                    _eventLogManager.EventCorrelationEngine.CorrelationAlert += EventCorrelationEngine_CorrelationAlert;
                    _eventLogManager.EventCorrelationEngine.CorrelationError += EventCorrelationEngine_CorrelationError;
                }

                // ThreatIntelligenceManager events
                if (_eventLogManager.ThreatIntelligenceManager != null)
                {
                    _eventLogManager.ThreatIntelligenceManager.ThreatIntelligenceUpdated += ThreatIntelligenceManager_ThreatIntelligenceUpdated;
                    _eventLogManager.ThreatIntelligenceManager.ThreatFeedUpdateError += ThreatIntelligenceManager_ThreatFeedUpdateError;
                }

                // RootkitDetector events
                if (_eventLogManager.RootkitDetector != null)
                {
                    _eventLogManager.RootkitDetector.RootkitDetection += RootkitDetector_RootkitDetection;
                    _eventLogManager.RootkitDetector.RootkitScanCompleted += RootkitDetector_RootkitScanCompleted;
                    _eventLogManager.RootkitDetector.RootkitScanError += RootkitDetector_RootkitScanError;
                }

                // EventLogManager events
                _eventLogManager.StatusChanged += EventLogManager_StatusChanged;
                _eventLogManager.ErrorOccurred += EventLogManager_ErrorOccurred;
            }
        }

        private void EventLogCollector_EventLogEntriesCollected(object sender, EventLogEntriesCollectedEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                UpdateStatusProperties();
                RefreshLogs();
            });
        }

        private void EventLogCollector_EventLogCollectionError(object sender, EventLogCollectionErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logger.LogError($"Event log collection error: {e.ErrorMessage}");
                // Could display in a status bar or error log view
            });
        }

        private void EventCorrelationEngine_CorrelationAlert(object sender, CorrelationAlertEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Add to alerts collection
                FilteredCorrelationAlerts.Insert(0, e.Alert);
                RecentAlerts.Insert(0, e.Alert);
                
                // Keep recent alerts limited to 10
                while (RecentAlerts.Count > 10)
                {
                    RecentAlerts.RemoveAt(RecentAlerts.Count - 1);
                }

                UpdateStatusProperties();

                // Show notification for high severity alerts
                if (e.Alert.Severity == AlertSeverity.High || e.Alert.Severity == AlertSeverity.Critical)
                {
                    // This would typically use a notification system
                    // For now, we'll just log it
                    Logger.LogWarning($"High severity alert: {e.Alert.Description}");
                }
            });
        }

        private void EventCorrelationEngine_CorrelationError(object sender, CorrelationErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logger.LogError($"Correlation engine error: {e.ErrorMessage}");
                // Could display in a status bar or error log view
            });
        }

        private void ThreatIntelligenceManager_ThreatIntelligenceUpdated(object sender, ThreatIntelligenceUpdatedEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                RefreshThreatIntelligence();
                UpdateStatusProperties();
                Logger.LogInfo($"Threat intelligence updated: {e.FeedName}");
            });
        }

        private void ThreatIntelligenceManager_ThreatFeedUpdateError(object sender, ThreatFeedUpdateErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logger.LogError($"Threat feed update error: {e.ErrorMessage}");
                // Could display in a status bar or error log view
            });
        }

        private void RootkitDetector_RootkitDetection(object sender, RootkitDetectionEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Add to detections collection
                FilteredRootkitDetections.Insert(0, e.Detection);
                UpdateStatusProperties();

                // Show notification for high severity detections
                if (e.Detection.Severity == RootkitSeverity.High || e.Detection.Severity == RootkitSeverity.Critical)
                {
                    // This would typically use a notification system
                    // For now, we'll just log it
                    Logger.LogWarning($"High severity rootkit detection: {e.Detection.Description}");
                }
            });
        }

        private void RootkitDetector_RootkitScanCompleted(object sender, RootkitScanCompletedEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                RefreshRootkitDetections();
                UpdateStatusProperties();
                Logger.LogInfo($"Rootkit scan completed: {e.DetectionsCount} detections found");
            });
        }

        private void RootkitDetector_RootkitScanError(object sender, RootkitScanErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logger.LogError($"Rootkit scan error: {e.ErrorMessage}");
                // Could display in a status bar or error log view
            });
        }

        private void EventLogManager_StatusChanged(object sender, EventLogManagerStatusEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                UpdateStatusProperties();
                Logger.LogInfo($"Event log manager status changed: {e.Status}");
            });
        }

        private void EventLogManager_ErrorOccurred(object sender, EventLogManagerErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Logger.LogError($"Event log manager error: {e.ErrorMessage}");
                // Could display in a status bar or error log view
            });
        }

        #endregion

        #region Helper Methods

        private void UpdateStatusProperties()
        {
            OnPropertyChanged(nameof(IsCollectionActive));
            OnPropertyChanged(nameof(IsCorrelationActive));
            OnPropertyChanged(nameof(IsRootkitDetectionActive));
            OnPropertyChanged(nameof(LogSourcesCount));
            OnPropertyChanged(nameof(CollectedEntriesCount));
            OnPropertyChanged(nameof(LastCollectionTime));
            OnPropertyChanged(nameof(ActiveRulesCount));
            OnPropertyChanged(nameof(AlertsCount));
            OnPropertyChanged(nameof(ThreatFeedsCount));
            OnPropertyChanged(nameof(RootkitDetectionsCount));
            OnPropertyChanged(nameof(LastRootkitScanTime));
        }

        private void LoadSettings()
        {
            try
            {   
                // Load settings from configuration
                // This would typically load from app.config or a custom settings file

                // Load log sources
                if (_eventLogManager?.EventLogCollector != null)
                {
                    ConfiguredLogSources.Clear();
                    foreach (var source in _eventLogManager.EventLogCollector.LogSources)
                    {
                        ConfiguredLogSources.Add(source);
                    }
                }

                // Load correlation rules
                if (_eventLogManager?.EventCorrelationEngine != null)
                {
                    CorrelationRules.Clear();
                    foreach (var rule in _eventLogManager.EventCorrelationEngine.ActiveRules)
                    {
                        CorrelationRules.Add(rule);
                    }
                }

                // Load threat feeds
                if (_eventLogManager?.ThreatIntelligenceManager != null)
                {
                    ThreatFeeds.Clear();
                    foreach (var feed in _eventLogManager.ThreatIntelligenceManager.ConfiguredFeeds)
                    {
                        ThreatFeeds.Add(feed);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error loading settings: {ex.Message}");
            }
        }

        #endregion

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    #region Converters

    public class AlertSeverityToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is AlertSeverity severity)
            {
                switch (severity)
                {
                    case AlertSeverity.Low:
                        return new SolidColorBrush(Colors.Green);
                    case AlertSeverity.Medium:
                        return new SolidColorBrush(Colors.Orange);
                    case AlertSeverity.High:
                        return new SolidColorBrush(Colors.Red);
                    case AlertSeverity.Critical:
                        return new SolidColorBrush(Colors.DarkRed);
                    default:
                        return new SolidColorBrush(Colors.Black);
                }
            }
            return new SolidColorBrush(Colors.Black);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class EventLogLevelToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is EventLogEntryLevel level)
            {
                switch (level)
                {
                    case EventLogEntryLevel.Information:
                        return new SolidColorBrush(Colors.Green);
                    case EventLogEntryLevel.Warning:
                        return new SolidColorBrush(Colors.Orange);
                    case EventLogEntryLevel.Error:
                        return new SolidColorBrush(Colors.Red);
                    case EventLogEntryLevel.Critical:
                        return new SolidColorBrush(Colors.DarkRed);
                    default:
                        return new SolidColorBrush(Colors.Black);
                }
            }
            return new SolidColorBrush(Colors.Black);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class RootkitSeverityToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is RootkitSeverity severity)
            {
                switch (severity)
                {
                    case RootkitSeverity.Low:
                        return new SolidColorBrush(Colors.Green);
                    case RootkitSeverity.Medium:
                        return new SolidColorBrush(Colors.Orange);
                    case RootkitSeverity.High:
                        return new SolidColorBrush(Colors.Red);
                    case RootkitSeverity.Critical:
                        return new SolidColorBrush(Colors.DarkRed);
                    default:
                        return new SolidColorBrush(Colors.Black);
                }
            }
            return new SolidColorBrush(Colors.Black);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class BooleanToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                return boolValue ? Visibility.Visible : Visibility.Collapsed;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Visibility visibility)
            {
                return visibility == Visibility.Visible;
            }
            return false;
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;

        public RelayCommand(Action execute) : this(_ => execute(), null) { }

        public RelayCommand(Action<object> execute) : this(execute, null) { }

        public RelayCommand(Action execute, Func<bool> canExecute) : this(_ => execute(), _ => canExecute()) { }

        public RelayCommand(Action<object> execute, Predicate<object> canExecute)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter)
        {
            return _canExecute == null || _canExecute(parameter);
        }

        public void Execute(object parameter)
        {
            _execute(parameter);
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }