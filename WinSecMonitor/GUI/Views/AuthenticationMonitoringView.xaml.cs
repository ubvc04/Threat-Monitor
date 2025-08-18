using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;
using WinSecMonitor.Modules.User;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.GUI.Views
{
    public partial class AuthenticationMonitoringView : UserControl, INotifyPropertyChanged
    {
        private readonly Logger _logger;
        private AuthenticationMonitor _authMonitor;
        private RDPSessionMonitor _rdpMonitor;
        private PrivilegeMonitor _privilegeMonitor;
        private AlertGenerator _alertGenerator;

        // Observable collections for UI binding
        private ObservableCollection<AuthenticationEvent> _authenticationEvents;
        private ObservableCollection<RDPSession> _rdpSessions;
        private ObservableCollection<PrivilegeEvent> _privilegeEvents;
        private ObservableCollection<SecurityAlert> _activeAlerts;
        private ObservableCollection<SecurityAlert> _alertHistory;

        // Filtered collections for search/filter functionality
        private ICollectionView _authEventsView;
        private ICollectionView _rdpSessionsView;
        private ICollectionView _privilegeEventsView;
        private ICollectionView _activeAlertsView;
        private ICollectionView _alertHistoryView;

        public event PropertyChangedEventHandler PropertyChanged;

        // Properties for data binding
        public ObservableCollection<AuthenticationEvent> AuthenticationEvents
        {
            get { return _authenticationEvents; }
            set
            {
                _authenticationEvents = value;
                OnPropertyChanged(nameof(AuthenticationEvents));
            }
        }

        public ObservableCollection<RDPSession> RDPSessions
        {
            get { return _rdpSessions; }
            set
            {
                _rdpSessions = value;
                OnPropertyChanged(nameof(RDPSessions));
            }
        }

        public ObservableCollection<PrivilegeEvent> PrivilegeEvents
        {
            get { return _privilegeEvents; }
            set
            {
                _privilegeEvents = value;
                OnPropertyChanged(nameof(PrivilegeEvents));
            }
        }

        public ObservableCollection<SecurityAlert> ActiveAlerts
        {
            get { return _activeAlerts; }
            set
            {
                _activeAlerts = value;
                OnPropertyChanged(nameof(ActiveAlerts));
            }
        }

        public ObservableCollection<SecurityAlert> AlertHistory
        {
            get { return _alertHistory; }
            set
            {
                _alertHistory = value;
                OnPropertyChanged(nameof(AlertHistory));
            }
        }

        public AuthenticationMonitoringView()
        {
            InitializeComponent();
            _logger = Logger.Instance;

            try
            {
                // Initialize monitoring components
                InitializeMonitors();

                // Set DataContext for binding
                DataContext = this;

                // Initialize collection views for filtering
                InitializeCollectionViews();

                // Update UI counters
                UpdateCounters();

                // Subscribe to alert events
                _alertGenerator.NewAlertGenerated += AlertGenerator_NewAlertGenerated;

                _logger.LogInformation("Authentication Monitoring View initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing Authentication Monitoring View");
                MessageBox.Show($"Error initializing Authentication Monitoring: {ex.Message}", "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void InitializeMonitors()
        {
            // Create monitoring components
            _authMonitor = new AuthenticationMonitor();
            _rdpMonitor = new RDPSessionMonitor();
            _privilegeMonitor = new PrivilegeMonitor();

            // Initialize alert generator with monitors
            _alertGenerator = new AlertGenerator(_authMonitor, _rdpMonitor, _privilegeMonitor, Dispatcher);

            // Initialize collections
            AuthenticationEvents = _authMonitor.AuthenticationEvents;
            RDPSessions = _rdpMonitor.RDPSessions;
            PrivilegeEvents = _privilegeMonitor.PrivilegeEvents;
            ActiveAlerts = _alertGenerator.ActiveAlerts;
            AlertHistory = _alertGenerator.AlertHistory;

            // Start monitoring
            _authMonitor.StartMonitoring();
            _rdpMonitor.StartMonitoring();
            _privilegeMonitor.StartMonitoring();
        }

        private void InitializeCollectionViews()
        {
            // Create collection views for filtering
            _authEventsView = CollectionViewSource.GetDefaultView(AuthenticationEvents);
            _rdpSessionsView = CollectionViewSource.GetDefaultView(RDPSessions);
            _privilegeEventsView = CollectionViewSource.GetDefaultView(PrivilegeEvents);
            _activeAlertsView = CollectionViewSource.GetDefaultView(ActiveAlerts);
            _alertHistoryView = CollectionViewSource.GetDefaultView(AlertHistory);

            // Set default sort descriptions (newest first)
            _authEventsView.SortDescriptions.Add(new SortDescription("Timestamp", ListSortDirection.Descending));
            _rdpSessionsView.SortDescriptions.Add(new SortDescription("ConnectTime", ListSortDirection.Descending));
            _privilegeEventsView.SortDescriptions.Add(new SortDescription("Timestamp", ListSortDirection.Descending));
            _activeAlertsView.SortDescriptions.Add(new SortDescription("Timestamp", ListSortDirection.Descending));
            _alertHistoryView.SortDescriptions.Add(new SortDescription("Timestamp", ListSortDirection.Descending));

            // Bind the views to the ListViews
            AuthEventsListView.ItemsSource = _authEventsView;
            RDPSessionsListView.ItemsSource = _rdpSessionsView;
            PrivilegeEventsListView.ItemsSource = _privilegeEventsView;
            AlertsListView.ItemsSource = _activeAlertsView;
            AlertHistoryListView.ItemsSource = _alertHistoryView;
        }

        private void UpdateCounters()
        {
            // Update count text blocks
            AuthEventsCountText.Text = $"Total Events: {_authEventsView.Cast<AuthenticationEvent>().Count()}";
            RDPSessionsCountText.Text = $"Total Sessions: {_rdpSessionsView.Cast<RDPSession>().Count()}";
            PrivilegeEventsCountText.Text = $"Total Events: {_privilegeEventsView.Cast<PrivilegeEvent>().Count()}";
            AlertsCountText.Text = $"Active Alerts: {_activeAlertsView.Cast<SecurityAlert>().Count()}";
            AlertHistoryCountText.Text = $"Total Alerts: {_alertHistoryView.Cast<SecurityAlert>().Count()}";
        }

        private void AlertGenerator_NewAlertGenerated(object sender, SecurityAlert e)
        {
            try
            {
                // Update counters when a new alert is generated
                Dispatcher.Invoke(() =>
                {
                    UpdateCounters();
                });
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error handling new alert");
            }
        }

        #region Event Handlers

        // Authentication Events Tab
        private void EventTypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ComboBoxItem selectedItem = (ComboBoxItem)EventTypeFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _authEventsView.Filter = item =>
                {
                    var authEvent = item as AuthenticationEvent;
                    if (authEvent == null) return false;

                    if (filter == "All Events") return true;
                    if (filter == "Successful Logons" && authEvent.EventType.Contains("Logon") && !authEvent.EventType.Contains("Failed")) return true;
                    if (filter == "Logoffs" && authEvent.EventType.Contains("Logoff")) return true;
                    if (filter == "Failed Logons" && authEvent.EventType.Contains("Failed")) return true;
                    if (filter == "Account Lockouts" && authEvent.EventType.Contains("Lockout")) return true;

                    return false;
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering authentication events");
            }
        }

        private void AuthEventSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                string searchText = AuthEventSearchBox.Text.ToLower();

                if (string.IsNullOrWhiteSpace(searchText))
                {
                    // If search box is empty, just apply the event type filter
                    EventTypeFilter_SelectionChanged(EventTypeFilter, null);
                    return;
                }

                // Get the current event type filter
                ComboBoxItem selectedItem = (ComboBoxItem)EventTypeFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _authEventsView.Filter = item =>
                {
                    var authEvent = item as AuthenticationEvent;
                    if (authEvent == null) return false;

                    // First apply the event type filter
                    bool passesTypeFilter = true;
                    if (filter != "All Events")
                    {
                        if (filter == "Successful Logons" && !(authEvent.EventType.Contains("Logon") && !authEvent.EventType.Contains("Failed"))) passesTypeFilter = false;
                        if (filter == "Logoffs" && !authEvent.EventType.Contains("Logoff")) passesTypeFilter = false;
                        if (filter == "Failed Logons" && !authEvent.EventType.Contains("Failed")) passesTypeFilter = false;
                        if (filter == "Account Lockouts" && !authEvent.EventType.Contains("Lockout")) passesTypeFilter = false;
                    }

                    if (!passesTypeFilter) return false;

                    // Then apply the search filter
                    return authEvent.Username.ToLower().Contains(searchText) ||
                           authEvent.Domain.ToLower().Contains(searchText) ||
                           authEvent.WorkstationName.ToLower().Contains(searchText) ||
                           authEvent.IpAddress.ToLower().Contains(searchText) ||
                           authEvent.Status.ToLower().Contains(searchText);
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error searching authentication events");
            }
        }

        private void RefreshAuthEventsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                _authMonitor.RefreshEvents();
                UpdateCounters();
                Mouse.OverrideCursor = null;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing authentication events");
                MessageBox.Show($"Error refreshing authentication events: {ex.Message}", "Refresh Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Mouse.OverrideCursor = null;
            }
        }

        // RDP Sessions Tab
        private void RDPSessionFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ComboBoxItem selectedItem = (ComboBoxItem)RDPSessionFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _rdpSessionsView.Filter = item =>
                {
                    var session = item as RDPSession;
                    if (session == null) return false;

                    if (filter == "All Sessions") return true;
                    if (filter == "Active Sessions" && session.SessionState == "Active") return true;
                    if (filter == "Disconnected Sessions" && session.SessionState == "Disconnected") return true;
                    if (filter == "Historical Sessions" && session.DisconnectTime.HasValue) return true;

                    return false;
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering RDP sessions");
            }
        }

        private void RDPSessionSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                string searchText = RDPSessionSearchBox.Text.ToLower();

                if (string.IsNullOrWhiteSpace(searchText))
                {
                    // If search box is empty, just apply the session filter
                    RDPSessionFilter_SelectionChanged(RDPSessionFilter, null);
                    return;
                }

                // Get the current session filter
                ComboBoxItem selectedItem = (ComboBoxItem)RDPSessionFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _rdpSessionsView.Filter = item =>
                {
                    var session = item as RDPSession;
                    if (session == null) return false;

                    // First apply the session filter
                    bool passesSessionFilter = true;
                    if (filter != "All Sessions")
                    {
                        if (filter == "Active Sessions" && session.SessionState != "Active") passesSessionFilter = false;
                        if (filter == "Disconnected Sessions" && session.SessionState != "Disconnected") passesSessionFilter = false;
                        if (filter == "Historical Sessions" && !session.DisconnectTime.HasValue) passesSessionFilter = false;
                    }

                    if (!passesSessionFilter) return false;

                    // Then apply the search filter
                    return session.Username.ToLower().Contains(searchText) ||
                           session.ClientName.ToLower().Contains(searchText) ||
                           session.ClientAddress.ToLower().Contains(searchText) ||
                           session.SessionId.ToString().Contains(searchText);
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error searching RDP sessions");
            }
        }

        private void RefreshRDPSessionsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                _rdpMonitor.RefreshSessions();
                UpdateCounters();
                Mouse.OverrideCursor = null;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing RDP sessions");
                MessageBox.Show($"Error refreshing RDP sessions: {ex.Message}", "Refresh Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Mouse.OverrideCursor = null;
            }
        }

        // Privilege Events Tab
        private void PrivilegeEventFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ComboBoxItem selectedItem = (ComboBoxItem)PrivilegeEventFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _privilegeEventsView.Filter = item =>
                {
                    var privEvent = item as PrivilegeEvent;
                    if (privEvent == null) return false;

                    if (filter == "All Events") return true;
                    if (filter == "Privilege Use" && privEvent.EventType.Contains("Privilege")) return true;
                    if (filter == "Group Changes" && privEvent.EventType.Contains("Group")) return true;
                    if (filter == "User Account Changes" && privEvent.EventType.Contains("User")) return true;
                    if (filter == "Process Elevation" && privEvent.EventType.Contains("Process")) return true;

                    return false;
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering privilege events");
            }
        }

        private void PrivilegeEventSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                string searchText = PrivilegeEventSearchBox.Text.ToLower();

                if (string.IsNullOrWhiteSpace(searchText))
                {
                    // If search box is empty, just apply the event filter
                    PrivilegeEventFilter_SelectionChanged(PrivilegeEventFilter, null);
                    return;
                }

                // Get the current event filter
                ComboBoxItem selectedItem = (ComboBoxItem)PrivilegeEventFilter.SelectedItem;
                string filter = selectedItem.Content.ToString();

                _privilegeEventsView.Filter = item =>
                {
                    var privEvent = item as PrivilegeEvent;
                    if (privEvent == null) return false;

                    // First apply the event filter
                    bool passesEventFilter = true;
                    if (filter != "All Events")
                    {
                        if (filter == "Privilege Use" && !privEvent.EventType.Contains("Privilege")) passesEventFilter = false;
                        if (filter == "Group Changes" && !privEvent.EventType.Contains("Group")) passesEventFilter = false;
                        if (filter == "User Account Changes" && !privEvent.EventType.Contains("User")) passesEventFilter = false;
                        if (filter == "Process Elevation" && !privEvent.EventType.Contains("Process")) passesEventFilter = false;
                    }

                    if (!passesEventFilter) return false;

                    // Then apply the search filter
                    return privEvent.Username.ToLower().Contains(searchText) ||
                           privEvent.Domain.ToLower().Contains(searchText) ||
                           privEvent.ProcessName.ToLower().Contains(searchText) ||
                           (privEvent.PrivilegeName?.ToLower().Contains(searchText) ?? false) ||
                           (privEvent.GroupName?.ToLower().Contains(searchText) ?? false) ||
                           privEvent.Action.ToLower().Contains(searchText);
                };

                UpdateCounters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error searching privilege events");
            }
        }

        private void RefreshPrivilegeEventsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Mouse.OverrideCursor = Cursors.Wait;
                _privilegeMonitor.RefreshEvents();
                UpdateCounters();
                Mouse.OverrideCursor = null;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing privilege events");
                MessageBox.Show($"Error refreshing privilege events: {ex.Message}", "Refresh Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Mouse.OverrideCursor = null;
            }
        }

        // Security Alerts Tab
        private void AlertTypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ApplyAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering alerts by type");
            }
        }

        private void AlertSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ApplyAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering alerts by severity");
            }
        }

        private void AlertSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                ApplyAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error searching alerts");
            }
        }

        private void ApplyAlertFilters()
        {
            ComboBoxItem typeItem = (ComboBoxItem)AlertTypeFilter.SelectedItem;
            string typeFilter = typeItem.Content.ToString();

            ComboBoxItem severityItem = (ComboBoxItem)AlertSeverityFilter.SelectedItem;
            string severityFilter = severityItem.Content.ToString();

            string searchText = AlertSearchBox.Text.ToLower();

            _activeAlertsView.Filter = item =>
            {
                var alert = item as SecurityAlert;
                if (alert == null) return false;

                // Apply type filter
                bool passesTypeFilter = true;
                if (typeFilter != "All Alerts")
                {
                    if (typeFilter == "Authentication Alerts" && alert.AlertType != "Authentication") passesTypeFilter = false;
                    if (typeFilter == "RDP Alerts" && alert.AlertType != "RDP") passesTypeFilter = false;
                    if (typeFilter == "Privilege Alerts" && alert.AlertType != "Privilege") passesTypeFilter = false;
                }

                if (!passesTypeFilter) return false;

                // Apply severity filter
                bool passesSeverityFilter = true;
                if (severityFilter != "All Severities")
                {
                    if (severityFilter != alert.FormattedSeverity) passesSeverityFilter = false;
                }

                if (!passesSeverityFilter) return false;

                // Apply search filter if not empty
                if (!string.IsNullOrWhiteSpace(searchText))
                {
                    return alert.Username.ToLower().Contains(searchText) ||
                           alert.Description.ToLower().Contains(searchText) ||
                           alert.Source.ToLower().Contains(searchText) ||
                           alert.Details.ToLower().Contains(searchText);
                }

                return true;
            };

            UpdateCounters();
        }

        private void AlertsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                var selectedAlert = AlertsListView.SelectedItem as SecurityAlert;
                if (selectedAlert != null)
                {
                    AlertDetailsTextBox.Text = selectedAlert.Details;
                    AcknowledgeAlertButton.IsEnabled = !selectedAlert.IsAcknowledged;
                }
                else
                {
                    AlertDetailsTextBox.Text = string.Empty;
                    AcknowledgeAlertButton.IsEnabled = false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error displaying alert details");
            }
        }

        private void AcknowledgeAlertButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedAlert = AlertsListView.SelectedItem as SecurityAlert;
                if (selectedAlert != null && !selectedAlert.IsAcknowledged)
                {
                    // Get current user for acknowledgment
                    string currentUser = Environment.UserName;
                    _alertGenerator.AcknowledgeAlert(selectedAlert, currentUser);
                    AcknowledgeAlertButton.IsEnabled = false;
                    UpdateCounters();
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging alert");
                MessageBox.Show($"Error acknowledging alert: {ex.Message}", "Acknowledgment Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AcknowledgeAllAlertsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ActiveAlerts.Count > 0)
                {
                    MessageBoxResult result = MessageBox.Show("Are you sure you want to acknowledge all active alerts?", "Confirm Acknowledgment", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        string currentUser = Environment.UserName;
                        _alertGenerator.AcknowledgeAllAlerts(currentUser);
                        AcknowledgeAlertButton.IsEnabled = false;
                        UpdateCounters();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging all alerts");
                MessageBox.Show($"Error acknowledging all alerts: {ex.Message}", "Acknowledgment Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ViewAlertHistoryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Switch to the Alert History tab
                TabControl tabControl = (TabControl)this.Content;
                tabControl.SelectedIndex = 4; // Index of the Alert History tab
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error switching to alert history tab");
            }
        }

        // Alert History Tab
        private void HistoryAlertTypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ApplyHistoryAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering alert history by type");
            }
        }

        private void HistoryAlertSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                ApplyHistoryAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error filtering alert history by severity");
            }
        }

        private void HistoryAlertSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                ApplyHistoryAlertFilters();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error searching alert history");
            }
        }

        private void ApplyHistoryAlertFilters()
        {
            ComboBoxItem typeItem = (ComboBoxItem)HistoryAlertTypeFilter.SelectedItem;
            string typeFilter = typeItem.Content.ToString();

            ComboBoxItem severityItem = (ComboBoxItem)HistoryAlertSeverityFilter.SelectedItem;
            string severityFilter = severityItem.Content.ToString();

            string searchText = HistoryAlertSearchBox.Text.ToLower();

            _alertHistoryView.Filter = item =>
            {
                var alert = item as SecurityAlert;
                if (alert == null) return false;

                // Apply type filter
                bool passesTypeFilter = true;
                if (typeFilter != "All Alerts")
                {
                    if (typeFilter == "Authentication Alerts" && alert.AlertType != "Authentication") passesTypeFilter = false;
                    if (typeFilter == "RDP Alerts" && alert.AlertType != "RDP") passesTypeFilter = false;
                    if (typeFilter == "Privilege Alerts" && alert.AlertType != "Privilege") passesTypeFilter = false;
                }

                if (!passesTypeFilter) return false;

                // Apply severity filter
                bool passesSeverityFilter = true;
                if (severityFilter != "All Severities")
                {
                    if (severityFilter != alert.FormattedSeverity) passesSeverityFilter = false;
                }

                if (!passesSeverityFilter) return false;

                // Apply search filter if not empty
                if (!string.IsNullOrWhiteSpace(searchText))
                {
                    return alert.Username.ToLower().Contains(searchText) ||
                           alert.Description.ToLower().Contains(searchText) ||
                           alert.Source.ToLower().Contains(searchText) ||
                           alert.Details.ToLower().Contains(searchText);
                }

                return true;
            };

            UpdateCounters();
        }

        private void AlertHistoryListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                var selectedAlert = AlertHistoryListView.SelectedItem as SecurityAlert;
                if (selectedAlert != null)
                {
                    HistoryAlertDetailsTextBox.Text = selectedAlert.Details;
                }
                else
                {
                    HistoryAlertDetailsTextBox.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error displaying alert history details");
            }
        }

        private void ExportAlertHistoryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (AlertHistory.Count == 0)
                {
                    MessageBox.Show("No alerts to export.", "Export Alert History", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // Create save file dialog
                SaveFileDialog saveFileDialog = new SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    DefaultExt = "csv",
                    Title = "Export Alert History"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    // Export alerts to CSV
                    using (StreamWriter writer = new StreamWriter(saveFileDialog.FileName, false, Encoding.UTF8))
                    {
                        // Write header
                        writer.WriteLine("Timestamp,Type,Source,Username,Severity,Description,Status");

                        // Write data
                        foreach (var alert in AlertHistory)
                        {
                            writer.WriteLine($"\"{alert.FormattedTimestamp}\",\"{alert.AlertType}\",\"{alert.Source}\",\"{alert.Username}\",\"{alert.FormattedSeverity}\",\"{alert.Description.Replace("\"", "\"\"")}\",\"{alert.Status}\"");
                        }
                    }

                    MessageBox.Show($"Alert history exported to {saveFileDialog.FileName}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error exporting alert history");
                MessageBox.Show($"Error exporting alert history: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearAlertHistoryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (AlertHistory.Count > 0)
                {
                    MessageBoxResult result = MessageBox.Show("Are you sure you want to clear the alert history? This action cannot be undone.", "Confirm Clear History", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (result == MessageBoxResult.Yes)
                    {
                        _alertGenerator.ClearAlertHistory();
                        HistoryAlertDetailsTextBox.Text = string.Empty;
                        UpdateCounters();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error clearing alert history");
                MessageBox.Show($"Error clearing alert history: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}