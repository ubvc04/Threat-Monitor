using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using WinSecMonitor.Modules.Network;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for NetworkMonitoringView.xaml
    /// </summary>
    public partial class NetworkMonitoringView : UserControl, INotifyPropertyChanged
    {
        #region Private Fields

        private readonly NetworkMonitoringManager _networkManager;
        private ObservableCollection<NetworkConnection> _filteredConnections;
        private ObservableCollection<NetworkAlert> _filteredAlerts;
        private string _connectionSearchText = string.Empty;
        private string _alertSearchText = string.Empty;
        private string _selectedConnectionFilter = "All";
        private string _selectedAlertSeverityFilter = "All";
        private string _newBlacklistIp = string.Empty;
        private string _newWhitelistIp = string.Empty;
        private string _newMaliciousDomain = string.Empty;
        private ObservableCollection<string> _blacklistedIps;
        private ObservableCollection<string> _whitelistedIps;
        private ObservableCollection<string> _maliciousDomains;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the filtered connections
        /// </summary>
        public ObservableCollection<NetworkConnection> FilteredConnections
        {
            get { return _filteredConnections; }
            private set
            {
                if (_filteredConnections != value)
                {
                    _filteredConnections = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets the filtered alerts
        /// </summary>
        public ObservableCollection<NetworkAlert> FilteredAlerts
        {
            get { return _filteredAlerts; }
            private set
            {
                if (_filteredAlerts != value)
                {
                    _filteredAlerts = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets or sets the connection search text
        /// </summary>
        public string ConnectionSearchText
        {
            get { return _connectionSearchText; }
            set
            {
                if (_connectionSearchText != value)
                {
                    _connectionSearchText = value;
                    OnPropertyChanged();
                    FilterConnections();
                }
            }
        }

        /// <summary>
        /// Gets or sets the alert search text
        /// </summary>
        public string AlertSearchText
        {
            get { return _alertSearchText; }
            set
            {
                if (_alertSearchText != value)
                {
                    _alertSearchText = value;
                    OnPropertyChanged();
                    FilterAlerts();
                }
            }
        }

        /// <summary>
        /// Gets the connection filter options
        /// </summary>
        public List<string> ConnectionFilterOptions { get; } = new List<string> { "All", "TCP", "UDP", "Suspicious" };

        /// <summary>
        /// Gets the alert severity filter options
        /// </summary>
        public List<string> AlertSeverityFilterOptions { get; } = new List<string> { "All", "Low", "Medium", "High", "Critical" };

        /// <summary>
        /// Gets or sets the selected connection filter
        /// </summary>
        public string SelectedConnectionFilter
        {
            get { return _selectedConnectionFilter; }
            set
            {
                if (_selectedConnectionFilter != value)
                {
                    _selectedConnectionFilter = value;
                    OnPropertyChanged();
                    FilterConnections();
                }
            }
        }

        /// <summary>
        /// Gets or sets the selected alert severity filter
        /// </summary>
        public string SelectedAlertSeverityFilter
        {
            get { return _selectedAlertSeverityFilter; }
            set
            {
                if (_selectedAlertSeverityFilter != value)
                {
                    _selectedAlertSeverityFilter = value;
                    OnPropertyChanged();
                    FilterAlerts();
                }
            }
        }

        /// <summary>
        /// Gets or sets the new blacklist IP
        /// </summary>
        public string NewBlacklistIp
        {
            get { return _newBlacklistIp; }
            set
            {
                if (_newBlacklistIp != value)
                {
                    _newBlacklistIp = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets or sets the new whitelist IP
        /// </summary>
        public string NewWhitelistIp
        {
            get { return _newWhitelistIp; }
            set
            {
                if (_newWhitelistIp != value)
                {
                    _newWhitelistIp = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets or sets the new malicious domain
        /// </summary>
        public string NewMaliciousDomain
        {
            get { return _newMaliciousDomain; }
            set
            {
                if (_newMaliciousDomain != value)
                {
                    _newMaliciousDomain = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets the blacklisted IPs
        /// </summary>
        public ObservableCollection<string> BlacklistedIps
        {
            get { return _blacklistedIps; }
            private set
            {
                if (_blacklistedIps != value)
                {
                    _blacklistedIps = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets the whitelisted IPs
        /// </summary>
        public ObservableCollection<string> WhitelistedIps
        {
            get { return _whitelistedIps; }
            private set
            {
                if (_whitelistedIps != value)
                {
                    _whitelistedIps = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets the malicious domains
        /// </summary>
        public ObservableCollection<string> MaliciousDomains
        {
            get { return _maliciousDomains; }
            private set
            {
                if (_maliciousDomains != value)
                {
                    _maliciousDomains = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets or sets the refresh interval
        /// </summary>
        public int RefreshInterval
        {
            get { return _networkManager.RefreshInterval; }
            set
            {
                if (_networkManager.RefreshInterval != value && value > 0)
                {
                    _networkManager.RefreshInterval = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Gets or sets the maximum number of alerts
        /// </summary>
        public int MaxAlerts
        {
            get { return _networkManager.MaxAlerts; }
            set
            {
                if (_networkManager.MaxAlerts != value && value > 0)
                {
                    _networkManager.MaxAlerts = value;
                    OnPropertyChanged();
                }
            }
        }

        #endregion

        #region Commands

        public ICommand StartMonitoringCommand { get; private set; }
        public ICommand StopMonitoringCommand { get; private set; }
        public ICommand RefreshConnectionsCommand { get; private set; }
        public ICommand ClearAlertsCommand { get; private set; }
        public ICommand ExportAlertsToCsvCommand { get; private set; }
        public ICommand AddToBlacklistCommand { get; private set; }
        public ICommand AddToWhitelistCommand { get; private set; }
        public ICommand AddToBlacklistManualCommand { get; private set; }
        public ICommand AddToWhitelistManualCommand { get; private set; }
        public ICommand RemoveFromBlacklistCommand { get; private set; }
        public ICommand RemoveFromWhitelistCommand { get; private set; }
        public ICommand LoadBlacklistFromFileCommand { get; private set; }
        public ICommand SaveBlacklistToFileCommand { get; private set; }
        public ICommand LoadWhitelistFromFileCommand { get; private set; }
        public ICommand SaveWhitelistToFileCommand { get; private set; }
        public ICommand AddMaliciousDomainCommand { get; private set; }
        public ICommand RemoveMaliciousDomainCommand { get; private set; }
        public ICommand LoadMaliciousDomainsFromFileCommand { get; private set; }
        public ICommand SaveMaliciousDomainsToFileCommand { get; private set; }
        public ICommand AddAlertIpToBlacklistCommand { get; private set; }
        public ICommand AddAlertIpToWhitelistCommand { get; private set; }
        public ICommand CopyIpAddressCommand { get; private set; }
        public ICommand CopyAlertIpAddressCommand { get; private set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the NetworkMonitoringView class
        /// </summary>
        public NetworkMonitoringView()
        {
            InitializeComponent();

            // Create the network monitoring manager
            _networkManager = new NetworkMonitoringManager();

            // Initialize collections
            _filteredConnections = new ObservableCollection<NetworkConnection>();
            _filteredAlerts = new ObservableCollection<NetworkAlert>();
            _blacklistedIps = new ObservableCollection<string>();
            _whitelistedIps = new ObservableCollection<string>();
            _maliciousDomains = new ObservableCollection<string>();

            // Initialize commands
            InitializeCommands();

            // Subscribe to events
            _networkManager.NetworkMonitor.ConnectionAdded += NetworkMonitor_ConnectionAdded;
            _networkManager.NetworkMonitor.ConnectionRemoved += NetworkMonitor_ConnectionRemoved;
            _networkManager.AlertAdded += NetworkManager_AlertAdded;

            // Set the data context
            DataContext = this;

            // Start monitoring
            _networkManager.StartMonitoring();

            // Initial filtering
            FilterConnections();
            FilterAlerts();

            // Load blacklisted and whitelisted IPs
            LoadBlacklistAndWhitelist();
        }

        #endregion

        #region Event Handlers

        /// <summary>
        /// Handles the ConnectionAdded event of the NetworkMonitor
        /// </summary>
        private void NetworkMonitor_ConnectionAdded(object sender, NetworkConnectionEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Add the connection to the filtered connections if it matches the filter
                if (MatchesConnectionFilter(e.Connection))
                {
                    _filteredConnections.Add(e.Connection);
                }
            });
        }

        /// <summary>
        /// Handles the ConnectionRemoved event of the NetworkMonitor
        /// </summary>
        private void NetworkMonitor_ConnectionRemoved(object sender, NetworkConnectionEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Remove the connection from the filtered connections
                var connection = _filteredConnections.FirstOrDefault(c => c.Id == e.Connection.Id);
                if (connection != null)
                {
                    _filteredConnections.Remove(connection);
                }
            });
        }

        /// <summary>
        /// Handles the AlertAdded event of the NetworkManager
        /// </summary>
        private void NetworkManager_AlertAdded(object sender, NetworkAlertEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Add the alert to the filtered alerts if it matches the filter
                if (MatchesAlertFilter(e.Alert))
                {
                    _filteredAlerts.Add(e.Alert);
                }
            });
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the commands
        /// </summary>
        private void InitializeCommands()
        {
            StartMonitoringCommand = new RelayCommand(param =>
            {
                try
                {
                    _networkManager.StartMonitoring();
                }
                catch (Exception ex)
                {
                    LogError($"Error starting monitoring: {ex.Message}");
                    MessageBox.Show($"Error starting monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => !_networkManager.IsMonitoring);

            StopMonitoringCommand = new RelayCommand(param =>
            {
                try
                {
                    _networkManager.StopMonitoring();
                }
                catch (Exception ex)
                {
                    LogError($"Error stopping monitoring: {ex.Message}");
                    MessageBox.Show($"Error stopping monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => _networkManager.IsMonitoring);

            RefreshConnectionsCommand = new RelayCommand(param =>
            {
                try
                {
                    _networkManager.RefreshConnections();
                }
                catch (Exception ex)
                {
                    LogError($"Error refreshing connections: {ex.Message}");
                    MessageBox.Show($"Error refreshing connections: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            ClearAlertsCommand = new RelayCommand(param =>
            {
                try
                {
                    _networkManager.ClearAlerts();
                    FilteredAlerts.Clear();
                }
                catch (Exception ex)
                {
                    LogError($"Error clearing alerts: {ex.Message}");
                    MessageBox.Show($"Error clearing alerts: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => _filteredAlerts.Count > 0);

            ExportAlertsToCsvCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create a save file dialog
                    var saveFileDialog = new SaveFileDialog
                    {
                        Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                        DefaultExt = "csv",
                        Title = "Export Alerts to CSV"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (saveFileDialog.ShowDialog() == true)
                    {
                        _networkManager.ExportAlertsToCsv(saveFileDialog.FileName);
                        MessageBox.Show($"Alerts exported to {saveFileDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error exporting alerts to CSV: {ex.Message}");
                    MessageBox.Show($"Error exporting alerts to CSV: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => _networkManager.Alerts.Count > 0);

            AddToBlacklistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkConnection connection)
                    {
                        _networkManager.AddToBlacklist(connection.RemoteAddress);
                        BlacklistedIps.Add(connection.RemoteAddress);
                        MessageBox.Show($"Added {connection.RemoteAddress} to blacklist", "Blacklist", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to blacklist: {ex.Message}");
                    MessageBox.Show($"Error adding to blacklist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            AddToWhitelistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkConnection connection)
                    {
                        _networkManager.AddToWhitelist(connection.RemoteAddress);
                        WhitelistedIps.Add(connection.RemoteAddress);
                        MessageBox.Show($"Added {connection.RemoteAddress} to whitelist", "Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to whitelist: {ex.Message}");
                    MessageBox.Show($"Error adding to whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            AddAlertIpToBlacklistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkAlert alert && !string.IsNullOrEmpty(alert.IpAddress))
                    {
                        _networkManager.AddToBlacklist(alert.IpAddress);
                        BlacklistedIps.Add(alert.IpAddress);
                        MessageBox.Show($"Added {alert.IpAddress} to blacklist", "Blacklist", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to blacklist: {ex.Message}");
                    MessageBox.Show($"Error adding to blacklist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            AddAlertIpToWhitelistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkAlert alert && !string.IsNullOrEmpty(alert.IpAddress))
                    {
                        _networkManager.AddToWhitelist(alert.IpAddress);
                        WhitelistedIps.Add(alert.IpAddress);
                        MessageBox.Show($"Added {alert.IpAddress} to whitelist", "Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to whitelist: {ex.Message}");
                    MessageBox.Show($"Error adding to whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            AddToBlacklistManualCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string ip && !string.IsNullOrWhiteSpace(ip))
                    {
                        _networkManager.AddToBlacklist(ip);
                        BlacklistedIps.Add(ip);
                        NewBlacklistIp = string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to blacklist: {ex.Message}");
                    MessageBox.Show($"Error adding to blacklist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => !string.IsNullOrWhiteSpace(param as string));

            AddToWhitelistManualCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string ip && !string.IsNullOrWhiteSpace(ip))
                    {
                        _networkManager.AddToWhitelist(ip);
                        WhitelistedIps.Add(ip);
                        NewWhitelistIp = string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding to whitelist: {ex.Message}");
                    MessageBox.Show($"Error adding to whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => !string.IsNullOrWhiteSpace(param as string));

            RemoveFromBlacklistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string ip)
                    {
                        _networkManager.RemoveFromBlacklist(ip);
                        BlacklistedIps.Remove(ip);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error removing from blacklist: {ex.Message}");
                    MessageBox.Show($"Error removing from blacklist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            RemoveFromWhitelistCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string ip)
                    {
                        _networkManager.RemoveFromWhitelist(ip);
                        WhitelistedIps.Remove(ip);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error removing from whitelist: {ex.Message}");
                    MessageBox.Show($"Error removing from whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            LoadBlacklistFromFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create an open file dialog
                    var openFileDialog = new OpenFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        Title = "Load Blacklist from File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (openFileDialog.ShowDialog() == true)
                    {
                        _networkManager.LoadBlacklistFromFile(openFileDialog.FileName);
                        LoadBlacklistAndWhitelist();
                        MessageBox.Show("Blacklist loaded successfully", "Load Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error loading blacklist from file: {ex.Message}");
                    MessageBox.Show($"Error loading blacklist from file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            SaveBlacklistToFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create a save file dialog
                    var saveFileDialog = new SaveFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        DefaultExt = "txt",
                        Title = "Save Blacklist to File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (saveFileDialog.ShowDialog() == true)
                    {
                        _networkManager.SaveBlacklistToFile(saveFileDialog.FileName);
                        MessageBox.Show("Blacklist saved successfully", "Save Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error saving blacklist to file: {ex.Message}");
                    MessageBox.Show($"Error saving blacklist to file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => BlacklistedIps.Count > 0);

            LoadWhitelistFromFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create an open file dialog
                    var openFileDialog = new OpenFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        Title = "Load Whitelist from File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (openFileDialog.ShowDialog() == true)
                    {
                        _networkManager.LoadWhitelistFromFile(openFileDialog.FileName);
                        LoadBlacklistAndWhitelist();
                        MessageBox.Show("Whitelist loaded successfully", "Load Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error loading whitelist from file: {ex.Message}");
                    MessageBox.Show($"Error loading whitelist from file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            SaveWhitelistToFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create a save file dialog
                    var saveFileDialog = new SaveFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        DefaultExt = "txt",
                        Title = "Save Whitelist to File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (saveFileDialog.ShowDialog() == true)
                    {
                        _networkManager.SaveWhitelistToFile(saveFileDialog.FileName);
                        MessageBox.Show("Whitelist saved successfully", "Save Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error saving whitelist to file: {ex.Message}");
                    MessageBox.Show($"Error saving whitelist to file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => WhitelistedIps.Count > 0);

            AddMaliciousDomainCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string domain && !string.IsNullOrWhiteSpace(domain))
                    {
                        _networkManager.AddMaliciousDomain(domain);
                        MaliciousDomains.Add(domain);
                        NewMaliciousDomain = string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error adding malicious domain: {ex.Message}");
                    MessageBox.Show($"Error adding malicious domain: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => !string.IsNullOrWhiteSpace(param as string));

            RemoveMaliciousDomainCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is string domain)
                    {
                        // Remove the domain from the collection
                        MaliciousDomains.Remove(domain);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error removing malicious domain: {ex.Message}");
                    MessageBox.Show($"Error removing malicious domain: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            LoadMaliciousDomainsFromFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create an open file dialog
                    var openFileDialog = new OpenFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        Title = "Load Malicious Domains from File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (openFileDialog.ShowDialog() == true)
                    {
                        _networkManager.LoadMaliciousDomainsFromFile(openFileDialog.FileName);
                        LoadMaliciousDomains();
                        MessageBox.Show("Malicious domains loaded successfully", "Load Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error loading malicious domains from file: {ex.Message}");
                    MessageBox.Show($"Error loading malicious domains from file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });

            SaveMaliciousDomainsToFileCommand = new RelayCommand(param =>
            {
                try
                {
                    // Create a save file dialog
                    var saveFileDialog = new SaveFileDialog
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        DefaultExt = "txt",
                        Title = "Save Malicious Domains to File"
                    };

                    // Show the dialog and check if the user clicked OK
                    if (saveFileDialog.ShowDialog() == true)
                    {
                        _networkManager.SaveMaliciousDomainsToFile(saveFileDialog.FileName);
                        MessageBox.Show("Malicious domains saved successfully", "Save Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error saving malicious domains to file: {ex.Message}");
                    MessageBox.Show($"Error saving malicious domains to file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }, param => MaliciousDomains.Count > 0);

            CopyIpAddressCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkConnection connection)
                    {
                        Clipboard.SetText(connection.RemoteAddress);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error copying IP address: {ex.Message}");
                }
            });

            CopyAlertIpAddressCommand = new RelayCommand(param =>
            {
                try
                {
                    if (param is NetworkAlert alert && !string.IsNullOrEmpty(alert.IpAddress))
                    {
                        Clipboard.SetText(alert.IpAddress);
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error copying IP address: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Filters the connections based on the search text and selected filter
        /// </summary>
        private void FilterConnections()
        {
            try
            {
                // Get all connections from the network monitor
                var connections = _networkManager.NetworkMonitor.Connections;

                // Filter the connections based on the search text and selected filter
                var filteredConnections = connections.Where(c => MatchesConnectionFilter(c)).ToList();

                // Update the filtered connections collection
                Application.Current.Dispatcher.Invoke(() =>
                {
                    FilteredConnections = new ObservableCollection<NetworkConnection>(filteredConnections);
                });
            }
            catch (Exception ex)
            {
                LogError($"Error filtering connections: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines if a connection matches the current filter
        /// </summary>
        private bool MatchesConnectionFilter(NetworkConnection connection)
        {
            // Check if the connection matches the selected filter
            bool matchesFilter = _selectedConnectionFilter == "All" ||
                                (_selectedConnectionFilter == "TCP" && connection.Protocol == "TCP") ||
                                (_selectedConnectionFilter == "UDP" && connection.Protocol == "UDP") ||
                                (_selectedConnectionFilter == "Suspicious" && connection.IsSuspicious);

            // Check if the connection matches the search text
            bool matchesSearch = string.IsNullOrEmpty(_connectionSearchText) ||
                                connection.RemoteAddress.Contains(_connectionSearchText) ||
                                connection.RemoteHostName.Contains(_connectionSearchText) ||
                                connection.ProcessName.Contains(_connectionSearchText) ||
                                connection.ServiceName.Contains(_connectionSearchText);

            return matchesFilter && matchesSearch;
        }

        /// <summary>
        /// Filters the alerts based on the search text and selected filter
        /// </summary>
        private void FilterAlerts()
        {
            try
            {
                // Get all alerts from the network manager
                var alerts = _networkManager.Alerts;

                // Filter the alerts based on the search text and selected filter
                var filteredAlerts = alerts.Where(a => MatchesAlertFilter(a)).ToList();

                // Update the filtered alerts collection
                Application.Current.Dispatcher.Invoke(() =>
                {
                    FilteredAlerts = new ObservableCollection<NetworkAlert>(filteredAlerts);
                });
            }
            catch (Exception ex)
            {
                LogError($"Error filtering alerts: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines if an alert matches the current filter
        /// </summary>
        private bool MatchesAlertFilter(NetworkAlert alert)
        {
            // Check if the alert matches the selected filter
            bool matchesFilter = _selectedAlertSeverityFilter == "All" ||
                                alert.Severity.ToString() == _selectedAlertSeverityFilter;

            // Check if the alert matches the search text
            bool matchesSearch = string.IsNullOrEmpty(_alertSearchText) ||
                                alert.Description.Contains(_alertSearchText) ||
                                alert.IpAddress.Contains(_alertSearchText) ||
                                alert.ProcessName.Contains(_alertSearchText) ||
                                alert.AlertType.Contains(_alertSearchText);

            return matchesFilter && matchesSearch;
        }

        /// <summary>
        /// Loads the blacklisted and whitelisted IPs from the network manager
        /// </summary>
        private void LoadBlacklistAndWhitelist()
        {
            try
            {
                // Get the blacklisted and whitelisted IPs from the network manager
                var blacklistedIps = _networkManager.BlacklistChecker.BlacklistedIps.ToList();
                var whitelistedIps = _networkManager.BlacklistChecker.WhitelistedIps.ToList();

                // Update the collections
                Application.Current.Dispatcher.Invoke(() =>
                {
                    BlacklistedIps = new ObservableCollection<string>(blacklistedIps);
                    WhitelistedIps = new ObservableCollection<string>(whitelistedIps);
                });
            }
            catch (Exception ex)
            {
                LogError($"Error loading blacklist and whitelist: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads the malicious domains from the network manager
        /// </summary>
        private void LoadMaliciousDomains()
        {
            try
            {
                // Get the malicious domains from the network manager
                var maliciousDomains = _networkManager.BlacklistChecker.MaliciousDomains.ToList();

                // Update the collection
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MaliciousDomains = new ObservableCollection<string>(maliciousDomains);
                });
            }
            catch (Exception ex)
            {
                LogError($"Error loading malicious domains: {ex.Message}");
            }
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [NetworkMonitoringView] {message}");
        }

        #endregion

        #region INotifyPropertyChanged Implementation

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    /// <summary>
    /// Converts an alert severity to a row style
    /// </summary>
    public class AlertSeverityToStyleConverter : IValueConverter
    {
        public Style HighSeverityStyle { get; set; }
        public Style MediumSeverityStyle { get; set; }
        public Style LowSeverityStyle { get; set; }

        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is AlertSeverity severity)
            {
                switch (severity)
                {
                    case AlertSeverity.High:
                    case AlertSeverity.Critical:
                        return HighSeverityStyle;
                    case AlertSeverity.Medium:
                        return MediumSeverityStyle;
                    case AlertSeverity.Low:
                        return LowSeverityStyle;
                }
            }

            return null;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A command that relays its functionality to other objects by invoking delegates
    /// </summary>
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;

        /// <summary>
        /// Initializes a new instance of the RelayCommand class
        /// </summary>
        public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        /// <summary>
        /// Determines whether this command can execute in its current state
        /// </summary>
        public bool CanExecute(object parameter)
        {
            return _canExecute == null || _canExecute(parameter);
        }

        /// <summary>
        /// Executes the command
        /// </summary>
        public void Execute(object parameter)
        {
            _execute(parameter);
        }

        /// <summary>
        /// Occurs when changes occur that affect whether or not the command should execute
        /// </summary>
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}