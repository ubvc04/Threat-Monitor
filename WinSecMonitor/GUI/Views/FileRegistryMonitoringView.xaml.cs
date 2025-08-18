using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;
using WinSecMonitor.Modules.FileRegistry;

namespace WinSecMonitor.GUI.Views
{
    /// <summary>
    /// Interaction logic for FileRegistryMonitoringView.xaml
    /// </summary>
    public partial class FileRegistryMonitoringView : UserControl, INotifyPropertyChanged
    {
        #region Private Fields

        private readonly FileRegistryMonitoringManager _monitoringManager;
        private string _fileSearchText = string.Empty;
        private string _registrySearchText = string.Empty;
        private string _newPathText = string.Empty;
        private string _newKeyPathText = string.Empty;
        private string _statusMessage = "Ready";
        private string _fileSeverityFilter = "All";
        private string _registrySeverityFilter = "All";
        private string _fileChangeTypeFilter = "All";
        private string _registryChangeTypeFilter = "All";
        private RegistryHive _selectedRegistryHive = RegistryHive.LocalMachine;
        private bool _includeSubKeys = true;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the monitoring manager
        /// </summary>
        public FileRegistryMonitoringManager MonitoringManager => _monitoringManager;

        /// <summary>
        /// Gets the configuration
        /// </summary>
        public FileRegistryConfiguration Configuration => _monitoringManager.Configuration;

        /// <summary>
        /// Gets whether monitoring is active
        /// </summary>
        public bool IsMonitoring => _monitoringManager.IsMonitoring;

        /// <summary>
        /// Gets the total number of file changes
        /// </summary>
        public int TotalFileChanges => _monitoringManager.TotalFileChanges;

        /// <summary>
        /// Gets the total number of registry changes
        /// </summary>
        public int TotalRegistryChanges => _monitoringManager.TotalRegistryChanges;

        /// <summary>
        /// Gets the number of high severity changes
        /// </summary>
        public int HighSeverityChanges => _monitoringManager.HighSeverityChanges;

        /// <summary>
        /// Gets or sets the file search text
        /// </summary>
        public string FileSearchText
        {
            get { return _fileSearchText; }
            set
            {
                if (_fileSearchText != value)
                {
                    _fileSearchText = value;
                    OnPropertyChanged(nameof(FileSearchText));
                    OnPropertyChanged(nameof(FilteredFileChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the registry search text
        /// </summary>
        public string RegistrySearchText
        {
            get { return _registrySearchText; }
            set
            {
                if (_registrySearchText != value)
                {
                    _registrySearchText = value;
                    OnPropertyChanged(nameof(RegistrySearchText));
                    OnPropertyChanged(nameof(FilteredRegistryChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the new path text
        /// </summary>
        public string NewPathText
        {
            get { return _newPathText; }
            set
            {
                if (_newPathText != value)
                {
                    _newPathText = value;
                    OnPropertyChanged(nameof(NewPathText));
                }
            }
        }

        /// <summary>
        /// Gets or sets the new key path text
        /// </summary>
        public string NewKeyPathText
        {
            get { return _newKeyPathText; }
            set
            {
                if (_newKeyPathText != value)
                {
                    _newKeyPathText = value;
                    OnPropertyChanged(nameof(NewKeyPathText));
                }
            }
        }

        /// <summary>
        /// Gets or sets the status message
        /// </summary>
        public string StatusMessage
        {
            get { return _statusMessage; }
            set
            {
                if (_statusMessage != value)
                {
                    _statusMessage = value;
                    OnPropertyChanged(nameof(StatusMessage));
                }
            }
        }

        /// <summary>
        /// Gets or sets the file severity filter
        /// </summary>
        public string FileSeverityFilter
        {
            get { return _fileSeverityFilter; }
            set
            {
                if (_fileSeverityFilter != value)
                {
                    _fileSeverityFilter = value;
                    OnPropertyChanged(nameof(FileSeverityFilter));
                    OnPropertyChanged(nameof(FilteredFileChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the registry severity filter
        /// </summary>
        public string RegistrySeverityFilter
        {
            get { return _registrySeverityFilter; }
            set
            {
                if (_registrySeverityFilter != value)
                {
                    _registrySeverityFilter = value;
                    OnPropertyChanged(nameof(RegistrySeverityFilter));
                    OnPropertyChanged(nameof(FilteredRegistryChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the file change type filter
        /// </summary>
        public string FileChangeTypeFilter
        {
            get { return _fileChangeTypeFilter; }
            set
            {
                if (_fileChangeTypeFilter != value)
                {
                    _fileChangeTypeFilter = value;
                    OnPropertyChanged(nameof(FileChangeTypeFilter));
                    OnPropertyChanged(nameof(FilteredFileChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the registry change type filter
        /// </summary>
        public string RegistryChangeTypeFilter
        {
            get { return _registryChangeTypeFilter; }
            set
            {
                if (_registryChangeTypeFilter != value)
                {
                    _registryChangeTypeFilter = value;
                    OnPropertyChanged(nameof(RegistryChangeTypeFilter));
                    OnPropertyChanged(nameof(FilteredRegistryChanges));
                }
            }
        }

        /// <summary>
        /// Gets or sets the selected registry hive
        /// </summary>
        public RegistryHive SelectedRegistryHive
        {
            get { return _selectedRegistryHive; }
            set
            {
                if (_selectedRegistryHive != value)
                {
                    _selectedRegistryHive = value;
                    OnPropertyChanged(nameof(SelectedRegistryHive));
                }
            }
        }

        /// <summary>
        /// Gets or sets whether to include subkeys
        /// </summary>
        public bool IncludeSubKeys
        {
            get { return _includeSubKeys; }
            set
            {
                if (_includeSubKeys != value)
                {
                    _includeSubKeys = value;
                    OnPropertyChanged(nameof(IncludeSubKeys));
                }
            }
        }

        /// <summary>
        /// Gets the filtered file changes
        /// </summary>
        public IEnumerable<FileChange> FilteredFileChanges
        {
            get
            {
                var changes = _monitoringManager.FileMonitor.FileChanges;

                // Apply search filter
                if (!string.IsNullOrWhiteSpace(FileSearchText))
                {
                    changes = changes.Where(c => 
                        c.Path.IndexOf(FileSearchText, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        c.ChangeType.ToString().IndexOf(FileSearchText, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (c.Details != null && c.Details.IndexOf(FileSearchText, StringComparison.OrdinalIgnoreCase) >= 0));
                }

                // Apply severity filter
                if (FileSeverityFilter != "All")
                {
                    ChangeSeverity severity = (ChangeSeverity)Enum.Parse(typeof(ChangeSeverity), FileSeverityFilter);
                    changes = changes.Where(c => c.Severity == severity);
                }

                // Apply change type filter
                if (FileChangeTypeFilter != "All")
                {
                    changes = changes.Where(c => c.ChangeType.ToString() == FileChangeTypeFilter);
                }

                return changes;
            }
        }

        /// <summary>
        /// Gets the filtered registry changes
        /// </summary>
        public IEnumerable<RegistryChange> FilteredRegistryChanges
        {
            get
            {
                var changes = _monitoringManager.RegistryMonitor.RegistryChanges;

                // Apply search filter
                if (!string.IsNullOrWhiteSpace(RegistrySearchText))
                {
                    changes = changes.Where(c => 
                        c.KeyPath.IndexOf(RegistrySearchText, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        c.ValueName.IndexOf(RegistrySearchText, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        c.ChangeType.ToString().IndexOf(RegistrySearchText, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                // Apply severity filter
                if (RegistrySeverityFilter != "All")
                {
                    ChangeSeverity severity = (ChangeSeverity)Enum.Parse(typeof(ChangeSeverity), RegistrySeverityFilter);
                    changes = changes.Where(c => c.Severity == severity);
                }

                // Apply change type filter
                if (RegistryChangeTypeFilter != "All")
                {
                    changes = changes.Where(c => c.ChangeType.ToString() == RegistryChangeTypeFilter);
                }

                return changes;
            }
        }

        /// <summary>
        /// Gets the severity filter options
        /// </summary>
        public ObservableCollection<string> SeverityFilterOptions { get; } = new ObservableCollection<string>
        {
            "All",
            "Low",
            "Medium",
            "High"
        };

        /// <summary>
        /// Gets the file change type filter options
        /// </summary>
        public ObservableCollection<string> FileChangeTypeFilterOptions { get; } = new ObservableCollection<string>
        {
            "All",
            "Created",
            "Modified",
            "Deleted",
            "Renamed"
        };

        /// <summary>
        /// Gets the registry change type filter options
        /// </summary>
        public ObservableCollection<string> RegistryChangeTypeFilterOptions { get; } = new ObservableCollection<string>
        {
            "All",
            "Added",
            "Modified",
            "Deleted"
        };

        /// <summary>
        /// Gets the registry hives
        /// </summary>
        public ObservableCollection<RegistryHive> RegistryHives { get; } = new ObservableCollection<RegistryHive>
        {
            RegistryHive.ClassesRoot,
            RegistryHive.CurrentUser,
            RegistryHive.LocalMachine,
            RegistryHive.Users,
            RegistryHive.CurrentConfig
        };

        #endregion

        #region Commands

        /// <summary>
        /// Gets the start monitoring command
        /// </summary>
        public ICommand StartMonitoringCommand { get; private set; }

        /// <summary>
        /// Gets the stop monitoring command
        /// </summary>
        public ICommand StopMonitoringCommand { get; private set; }

        /// <summary>
        /// Gets the refresh command
        /// </summary>
        public ICommand RefreshCommand { get; private set; }

        /// <summary>
        /// Gets the clear all command
        /// </summary>
        public ICommand ClearAllCommand { get; private set; }

        /// <summary>
        /// Gets the clear file changes command
        /// </summary>
        public ICommand ClearFileChangesCommand { get; private set; }

        /// <summary>
        /// Gets the clear registry changes command
        /// </summary>
        public ICommand ClearRegistryChangesCommand { get; private set; }

        /// <summary>
        /// Gets the export file changes command
        /// </summary>
        public ICommand ExportFileChangesCommand { get; private set; }

        /// <summary>
        /// Gets the export registry changes command
        /// </summary>
        public ICommand ExportRegistryChangesCommand { get; private set; }

        /// <summary>
        /// Gets the add path command
        /// </summary>
        public ICommand AddPathCommand { get; private set; }

        /// <summary>
        /// Gets the remove path command
        /// </summary>
        public ICommand RemovePathCommand { get; private set; }

        /// <summary>
        /// Gets the browse path command
        /// </summary>
        public ICommand BrowsePathCommand { get; private set; }

        /// <summary>
        /// Gets the add key command
        /// </summary>
        public ICommand AddKeyCommand { get; private set; }

        /// <summary>
        /// Gets the remove key command
        /// </summary>
        public ICommand RemoveKeyCommand { get; private set; }

        /// <summary>
        /// Gets the save config command
        /// </summary>
        public ICommand SaveConfigCommand { get; private set; }

        /// <summary>
        /// Gets the load config command
        /// </summary>
        public ICommand LoadConfigCommand { get; private set; }

        /// <summary>
        /// Gets the reset config command
        /// </summary>
        public ICommand ResetConfigCommand { get; private set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the FileRegistryMonitoringView class
        /// </summary>
        public FileRegistryMonitoringView()
        {
            try
            {
                // Create monitoring manager
                _monitoringManager = new FileRegistryMonitoringManager();

                // Initialize commands
                InitializeCommands();

                // Initialize component
                InitializeComponent();

                // Set data context
                DataContext = this;

                // Subscribe to property changed events
                _monitoringManager.PropertyChanged += OnMonitoringManagerPropertyChanged;

                // Set status message
                StatusMessage = "File and Registry Monitoring initialized";

                // Log initialization
                LogInfo("FileRegistryMonitoringView initialized");
            }
            catch (Exception ex)
            {
                LogError($"Error initializing FileRegistryMonitoringView: {ex.Message}");
                MessageBox.Show($"Error initializing File and Registry Monitoring: {ex.Message}", "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the commands
        /// </summary>
        private void InitializeCommands()
        {
            StartMonitoringCommand = new RelayCommand(StartMonitoring);
            StopMonitoringCommand = new RelayCommand(StopMonitoring);
            RefreshCommand = new RelayCommand(RefreshData);
            ClearAllCommand = new RelayCommand(ClearAllChanges);
            ClearFileChangesCommand = new RelayCommand(ClearFileChanges);
            ClearRegistryChangesCommand = new RelayCommand(ClearRegistryChanges);
            ExportFileChangesCommand = new RelayCommand(ExportFileChanges);
            ExportRegistryChangesCommand = new RelayCommand(ExportRegistryChanges);
            AddPathCommand = new RelayCommand(AddPath);
            RemovePathCommand = new RelayCommand<string>(RemovePath);
            BrowsePathCommand = new RelayCommand(BrowsePath);
            AddKeyCommand = new RelayCommand(AddKey);
            RemoveKeyCommand = new RelayCommand<RegistryKeyPath>(RemoveKey);
            SaveConfigCommand = new RelayCommand(SaveConfig);
            LoadConfigCommand = new RelayCommand(LoadConfig);
            ResetConfigCommand = new RelayCommand(ResetConfig);
        }

        /// <summary>
        /// Handles the monitoring manager property changed event
        /// </summary>
        private void OnMonitoringManagerPropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            // Update properties when monitoring manager properties change
            switch (e.PropertyName)
            {
                case nameof(FileRegistryMonitoringManager.IsMonitoring):
                    OnPropertyChanged(nameof(IsMonitoring));
                    break;
                case nameof(FileRegistryMonitoringManager.TotalFileChanges):
                    OnPropertyChanged(nameof(TotalFileChanges));
                    OnPropertyChanged(nameof(FilteredFileChanges));
                    break;
                case nameof(FileRegistryMonitoringManager.TotalRegistryChanges):
                    OnPropertyChanged(nameof(TotalRegistryChanges));
                    OnPropertyChanged(nameof(FilteredRegistryChanges));
                    break;
                case nameof(FileRegistryMonitoringManager.HighSeverityChanges):
                    OnPropertyChanged(nameof(HighSeverityChanges));
                    break;
            }
        }

        /// <summary>
        /// Starts monitoring
        /// </summary>
        private void StartMonitoring(object parameter)
        {
            try
            {
                _monitoringManager.StartMonitoring();
                StatusMessage = "Monitoring started";
                LogInfo("Monitoring started");
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error starting monitoring: {ex.Message}";
                LogError($"Error starting monitoring: {ex.Message}");
                MessageBox.Show($"Error starting monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Stops monitoring
        /// </summary>
        private void StopMonitoring(object parameter)
        {
            try
            {
                _monitoringManager.StopMonitoring();
                StatusMessage = "Monitoring stopped";
                LogInfo("Monitoring stopped");
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error stopping monitoring: {ex.Message}";
                LogError($"Error stopping monitoring: {ex.Message}");
                MessageBox.Show($"Error stopping monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Refreshes monitoring data
        /// </summary>
        private void RefreshData(object parameter)
        {
            try
            {
                _monitoringManager.RefreshData();
                StatusMessage = "Data refreshed";
                LogInfo("Data refreshed");

                // Update filtered collections
                OnPropertyChanged(nameof(FilteredFileChanges));
                OnPropertyChanged(nameof(FilteredRegistryChanges));
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error refreshing data: {ex.Message}";
                LogError($"Error refreshing data: {ex.Message}");
                MessageBox.Show($"Error refreshing data: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Clears all changes
        /// </summary>
        private void ClearAllChanges(object parameter)
        {
            try
            {
                _monitoringManager.ClearAllChanges();
                StatusMessage = "All changes cleared";
                LogInfo("All changes cleared");

                // Update filtered collections
                OnPropertyChanged(nameof(FilteredFileChanges));
                OnPropertyChanged(nameof(FilteredRegistryChanges));
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error clearing changes: {ex.Message}";
                LogError($"Error clearing changes: {ex.Message}");
                MessageBox.Show($"Error clearing changes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Clears file changes
        /// </summary>
        private void ClearFileChanges(object parameter)
        {
            try
            {
                _monitoringManager.FileMonitor.ClearChanges();
                _monitoringManager.UpdateStatistics();
                StatusMessage = "File changes cleared";
                LogInfo("File changes cleared");

                // Update filtered collections
                OnPropertyChanged(nameof(FilteredFileChanges));
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error clearing file changes: {ex.Message}";
                LogError($"Error clearing file changes: {ex.Message}");
                MessageBox.Show($"Error clearing file changes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Clears registry changes
        /// </summary>
        private void ClearRegistryChanges(object parameter)
        {
            try
            {
                _monitoringManager.RegistryMonitor.ClearChanges();
                _monitoringManager.UpdateStatistics();
                StatusMessage = "Registry changes cleared";
                LogInfo("Registry changes cleared");

                // Update filtered collections
                OnPropertyChanged(nameof(FilteredRegistryChanges));
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error clearing registry changes: {ex.Message}";
                LogError($"Error clearing registry changes: {ex.Message}");
                MessageBox.Show($"Error clearing registry changes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Exports file changes to CSV
        /// </summary>
        private void ExportFileChanges(object parameter)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv",
                    DefaultExt = ".csv",
                    FileName = $"FileChanges_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    bool result = _monitoringManager.FileMonitor.ExportChangesToCsv(dialog.FileName);
                    if (result)
                    {
                        StatusMessage = $"File changes exported to {dialog.FileName}";
                        LogInfo($"File changes exported to {dialog.FileName}");
                    }
                    else
                    {
                        StatusMessage = "Error exporting file changes";
                        LogWarning("Error exporting file changes");
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error exporting file changes: {ex.Message}";
                LogError($"Error exporting file changes: {ex.Message}");
                MessageBox.Show($"Error exporting file changes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Exports registry changes to CSV
        /// </summary>
        private void ExportRegistryChanges(object parameter)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv",
                    DefaultExt = ".csv",
                    FileName = $"RegistryChanges_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    bool result = _monitoringManager.RegistryMonitor.ExportChangesToCsv(dialog.FileName);
                    if (result)
                    {
                        StatusMessage = $"Registry changes exported to {dialog.FileName}";
                        LogInfo($"Registry changes exported to {dialog.FileName}");
                    }
                    else
                    {
                        StatusMessage = "Error exporting registry changes";
                        LogWarning("Error exporting registry changes");
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error exporting registry changes: {ex.Message}";
                LogError($"Error exporting registry changes: {ex.Message}");
                MessageBox.Show($"Error exporting registry changes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Adds a path to monitor
        /// </summary>
        private void AddPath(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(NewPathText))
                {
                    MessageBox.Show("Please enter a valid path", "Invalid Path", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                bool result = _monitoringManager.Configuration.AddMonitoredPath(NewPathText);
                if (result)
                {
                    StatusMessage = $"Path added: {NewPathText}";
                    LogInfo($"Path added: {NewPathText}");
                    NewPathText = string.Empty;
                }
                else
                {
                    StatusMessage = $"Error adding path: {NewPathText}";
                    LogWarning($"Error adding path: {NewPathText}");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error adding path: {ex.Message}";
                LogError($"Error adding path: {ex.Message}");
                MessageBox.Show($"Error adding path: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Removes a path from monitoring
        /// </summary>
        private void RemovePath(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    return;
                }

                bool result = _monitoringManager.Configuration.RemoveMonitoredPath(path);
                if (result)
                {
                    StatusMessage = $"Path removed: {path}";
                    LogInfo($"Path removed: {path}");
                }
                else
                {
                    StatusMessage = $"Error removing path: {path}";
                    LogWarning($"Error removing path: {path}");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error removing path: {ex.Message}";
                LogError($"Error removing path: {ex.Message}");
                MessageBox.Show($"Error removing path: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Browses for a path to monitor
        /// </summary>
        private void BrowsePath(object parameter)
        {
            try
            {
                var dialog = new System.Windows.Forms.FolderBrowserDialog
                {
                    Description = "Select a folder to monitor",
                    ShowNewFolderButton = false
                };

                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    NewPathText = dialog.SelectedPath;
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error browsing for path: {ex.Message}";
                LogError($"Error browsing for path: {ex.Message}");
                MessageBox.Show($"Error browsing for path: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Adds a registry key to monitor
        /// </summary>
        private void AddKey(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(NewKeyPathText))
                {
                    MessageBox.Show("Please enter a valid registry key path", "Invalid Key Path", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var keyPath = new RegistryKeyPath(SelectedRegistryHive, NewKeyPathText, IncludeSubKeys);
                bool result = _monitoringManager.Configuration.AddMonitoredRegistryKey(keyPath);
                if (result)
                {
                    StatusMessage = $"Registry key added: {keyPath.FullPath}";
                    LogInfo($"Registry key added: {keyPath.FullPath}");
                    NewKeyPathText = string.Empty;
                }
                else
                {
                    StatusMessage = $"Error adding registry key: {keyPath.FullPath}";
                    LogWarning($"Error adding registry key: {keyPath.FullPath}");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error adding registry key: {ex.Message}";
                LogError($"Error adding registry key: {ex.Message}");
                MessageBox.Show($"Error adding registry key: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Removes a registry key from monitoring
        /// </summary>
        private void RemoveKey(RegistryKeyPath keyPath)
        {
            try
            {
                if (keyPath == null)
                {
                    return;
                }

                bool result = _monitoringManager.Configuration.RemoveMonitoredRegistryKey(keyPath);
                if (result)
                {
                    StatusMessage = $"Registry key removed: {keyPath.FullPath}";
                    LogInfo($"Registry key removed: {keyPath.FullPath}");
                }
                else
                {
                    StatusMessage = $"Error removing registry key: {keyPath.FullPath}";
                    LogWarning($"Error removing registry key: {keyPath.FullPath}");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error removing registry key: {ex.Message}";
                LogError($"Error removing registry key: {ex.Message}");
                MessageBox.Show($"Error removing registry key: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Saves the configuration to a file
        /// </summary>
        private void SaveConfig(object parameter)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "XML Files (*.xml)|*.xml",
                    DefaultExt = ".xml",
                    FileName = "FileRegistryMonitoring.xml"
                };

                if (dialog.ShowDialog() == true)
                {
                    _monitoringManager.SaveConfiguration(dialog.FileName);
                    StatusMessage = $"Configuration saved to {dialog.FileName}";
                    LogInfo($"Configuration saved to {dialog.FileName}");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error saving configuration: {ex.Message}";
                LogError($"Error saving configuration: {ex.Message}");
                MessageBox.Show($"Error saving configuration: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Loads the configuration from a file
        /// </summary>
        private void LoadConfig(object parameter)
        {
            try
            {
                var dialog = new OpenFileDialog
                {
                    Filter = "XML Files (*.xml)|*.xml",
                    DefaultExt = ".xml"
                };

                if (dialog.ShowDialog() == true)
                {
                    bool result = _monitoringManager.LoadConfiguration(dialog.FileName);
                    if (result)
                    {
                        StatusMessage = $"Configuration loaded from {dialog.FileName}";
                        LogInfo($"Configuration loaded from {dialog.FileName}");
                    }
                    else
                    {
                        StatusMessage = $"Error loading configuration from {dialog.FileName}";
                        LogWarning($"Error loading configuration from {dialog.FileName}");
                    }
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error loading configuration: {ex.Message}";
                LogError($"Error loading configuration: {ex.Message}");
                MessageBox.Show($"Error loading configuration: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Resets the configuration to defaults
        /// </summary>
        private void ResetConfig(object parameter)
        {
            try
            {
                if (MessageBox.Show("Are you sure you want to reset the configuration to defaults?", "Confirm Reset", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _monitoringManager.Configuration.ResetToDefaults();
                    StatusMessage = "Configuration reset to defaults";
                    LogInfo("Configuration reset to defaults");
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error resetting configuration: {ex.Message}";
                LogError($"Error resetting configuration: {ex.Message}");
                MessageBox.Show($"Error resetting configuration: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [FileRegistryMonitoringView] {message}");
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        private void LogWarning(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[WARNING] [FileRegistryMonitoringView] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [FileRegistryMonitoringView] {message}");
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

    /// <summary>
    /// Relay command implementation
    /// </summary>
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;

        public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
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

    /// <summary>
    /// Generic relay command implementation
    /// </summary>
    public class RelayCommand<T> : ICommand
    {
        private readonly Action<T> _execute;
        private readonly Predicate<T> _canExecute;

        public RelayCommand(Action<T> execute, Predicate<T> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter)
        {
            return _canExecute == null || _canExecute((T)parameter);
        }

        public void Execute(object parameter)
        {
            _execute((T)parameter);
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}