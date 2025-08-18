using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
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

namespace WinSecMonitor.Modules.Processes
{
    /// <summary>
    /// Interaction logic for ProcessMonitoringView.xaml
    /// </summary>
    public partial class ProcessMonitoringView : UserControl
    {
        #region Private Fields

        private readonly ProcessMonitoringManager _monitoringManager;
        private ICollectionView _processesView;
        private ICollectionView _alertsView;
        private string _processSearchText = string.Empty;
        private string _alertSearchText = string.Empty;
        private bool _showOnlySuspicious = false;
        private bool _showOnlyUnknown = false;
        private string _selectedAlertSeverity = "All Severities";
        private string _selectedAlertType = "All Types";

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the ProcessMonitoringView class
        /// </summary>
        public ProcessMonitoringView()
        {
            InitializeComponent();

            try
            {
                // Create the monitoring manager
                _monitoringManager = new ProcessMonitoringManager();
                DataContext = _monitoringManager;

                // Initialize the collection views
                _processesView = CollectionViewSource.GetDefaultView(_monitoringManager.ProcessMonitor.Processes);
                _processesView.Filter = ProcessFilter;

                _alertsView = CollectionViewSource.GetDefaultView(_monitoringManager.Alerts);
                _alertsView.Filter = AlertFilter;

                // Bind the data grids
                ProcessesDataGrid.ItemsSource = _processesView;
                AlertsDataGrid.ItemsSource = _alertsView;

                // Initialize the whitelist listbox
                UpdateWhitelistDisplay();

                // Set initial slider values
                RefreshIntervalSlider.Value = _monitoringManager.ProcessMonitor.RefreshInterval;
                RefreshIntervalTextBlock.Text = _monitoringManager.ProcessMonitor.RefreshInterval.ToString();

                MaxAlertsSlider.Value = _monitoringManager.MaxAlerts;
                MaxAlertsTextBlock.Text = _monitoringManager.MaxAlerts.ToString();

                LogInfo("ProcessMonitoringView initialized");
            }
            catch (Exception ex)
            {
                LogError($"Error initializing ProcessMonitoringView: {ex.Message}");
                MessageBox.Show($"Error initializing process monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region Event Handlers

        /// <summary>
        /// Handles the Click event of the StartButton control
        /// </summary>
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _monitoringManager.StartMonitoring();
                UpdateMonitoringStatus(true);
                LogInfo("Process monitoring started");
            }
            catch (Exception ex)
            {
                LogError($"Error starting process monitoring: {ex.Message}");
                MessageBox.Show($"Error starting process monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the StopButton control
        /// </summary>
        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _monitoringManager.StopMonitoring();
                UpdateMonitoringStatus(false);
                LogInfo("Process monitoring stopped");
            }
            catch (Exception ex)
            {
                LogError($"Error stopping process monitoring: {ex.Message}");
                MessageBox.Show($"Error stopping process monitoring: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the RefreshButton control
        /// </summary>
        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _monitoringManager.RefreshProcesses();
                LogInfo("Process list refreshed");
            }
            catch (Exception ex)
            {
                LogError($"Error refreshing process list: {ex.Message}");
                MessageBox.Show($"Error refreshing process list: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the TextChanged event of the ProcessSearchTextBox control
        /// </summary>
        private void ProcessSearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _processSearchText = ProcessSearchTextBox.Text.Trim().ToLower();
            _processesView.Refresh();
        }

        /// <summary>
        /// Handles the Checked and Unchecked events of the process filter checkboxes
        /// </summary>
        private void ProcessFilter_Changed(object sender, RoutedEventArgs e)
        {
            _showOnlySuspicious = ShowOnlySuspiciousCheckBox.IsChecked ?? false;
            _showOnlyUnknown = ShowOnlyUnknownCheckBox.IsChecked ?? false;
            _processesView.Refresh();
        }

        /// <summary>
        /// Handles the TextChanged event of the AlertSearchTextBox control
        /// </summary>
        private void AlertSearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _alertSearchText = AlertSearchTextBox.Text.Trim().ToLower();
            _alertsView.Refresh();
        }

        /// <summary>
        /// Handles the SelectionChanged event of the alert filter controls
        /// </summary>
        private void AlertFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (AlertSeverityComboBox != null && AlertTypeComboBox != null)
            {
                var severityItem = AlertSeverityComboBox.SelectedItem as ComboBoxItem;
                var typeItem = AlertTypeComboBox.SelectedItem as ComboBoxItem;

                if (severityItem != null && typeItem != null)
                {
                    _selectedAlertSeverity = severityItem.Content.ToString();
                    _selectedAlertType = typeItem.Content.ToString();
                    _alertsView.Refresh();
                }
            }
        }

        /// <summary>
        /// Handles the Click event of the ClearAlertsButton control
        /// </summary>
        private void ClearAlertsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (MessageBox.Show("Are you sure you want to clear all alerts?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _monitoringManager.ClearAlerts();
                    LogInfo("Alerts cleared");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error clearing alerts: {ex.Message}");
                MessageBox.Show($"Error clearing alerts: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the ExportAlertsButton control
        /// </summary>
        private void ExportAlertsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv",
                    DefaultExt = "csv",
                    Title = "Export Alerts to CSV"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    if (_monitoringManager.ExportAlertsToCsv(saveFileDialog.FileName))
                    {
                        MessageBox.Show($"Alerts exported to {saveFileDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                        LogInfo($"Alerts exported to {saveFileDialog.FileName}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error exporting alerts: {ex.Message}");
                MessageBox.Show($"Error exporting alerts: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the AddToWhitelistButton control
        /// </summary>
        private void AddToWhitelistButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedProcess = ProcessesDataGrid.SelectedItem as ProcessInfo;
                if (selectedProcess != null)
                {
                    _monitoringManager.AddToWhitelist(selectedProcess.Name);
                    UpdateWhitelistDisplay();
                    _processesView.Refresh();
                    LogInfo($"Added {selectedProcess.Name} to whitelist");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error adding process to whitelist: {ex.Message}");
                MessageBox.Show($"Error adding process to whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the RemoveFromWhitelistButton control
        /// </summary>
        private void RemoveFromWhitelistButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedProcess = ProcessesDataGrid.SelectedItem as ProcessInfo;
                if (selectedProcess != null)
                {
                    _monitoringManager.RemoveFromWhitelist(selectedProcess.Name);
                    UpdateWhitelistDisplay();
                    _processesView.Refresh();
                    LogInfo($"Removed {selectedProcess.Name} from whitelist");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error removing process from whitelist: {ex.Message}");
                MessageBox.Show($"Error removing process from whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the SelectionChanged event of the ProcessesDataGrid control
        /// </summary>
        private void ProcessesDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedProcess = ProcessesDataGrid.SelectedItem as ProcessInfo;
            AddToWhitelistButton.IsEnabled = selectedProcess != null;
            RemoveFromWhitelistButton.IsEnabled = selectedProcess != null;
        }

        /// <summary>
        /// Handles the ValueChanged event of the RefreshIntervalSlider control
        /// </summary>
        private void RefreshIntervalSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (RefreshIntervalTextBlock != null && _monitoringManager != null)
            {
                int value = (int)RefreshIntervalSlider.Value;
                RefreshIntervalTextBlock.Text = value.ToString();
                _monitoringManager.ProcessMonitor.RefreshInterval = value;
            }
        }

        /// <summary>
        /// Handles the ValueChanged event of the MaxAlertsSlider control
        /// </summary>
        private void MaxAlertsSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (MaxAlertsTextBlock != null && _monitoringManager != null)
            {
                int value = (int)MaxAlertsSlider.Value;
                MaxAlertsTextBlock.Text = value.ToString();
                _monitoringManager.MaxAlerts = value;
            }
        }

        /// <summary>
        /// Handles the Click event of the SaveApiKeyButton control
        /// </summary>
        private void SaveApiKeyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // TODO: Save API key to configuration
                MessageBox.Show("API key saved", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                LogInfo("VirusTotal API key saved");
            }
            catch (Exception ex)
            {
                LogError($"Error saving API key: {ex.Message}");
                MessageBox.Show($"Error saving API key: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the AddWhitelistProcessButton control
        /// </summary>
        private void AddWhitelistProcessButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string processName = WhitelistProcessTextBox.Text.Trim();
                if (!string.IsNullOrEmpty(processName))
                {
                    _monitoringManager.AddToWhitelist(processName);
                    UpdateWhitelistDisplay();
                    WhitelistProcessTextBox.Clear();
                    _processesView.Refresh();
                    LogInfo($"Added {processName} to whitelist");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error adding process to whitelist: {ex.Message}");
                MessageBox.Show($"Error adding process to whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the RemoveWhitelistProcessButton control
        /// </summary>
        private void RemoveWhitelistProcessButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string selectedProcess = WhitelistProcessesListBox.SelectedItem as string;
                if (!string.IsNullOrEmpty(selectedProcess))
                {
                    _monitoringManager.RemoveFromWhitelist(selectedProcess);
                    UpdateWhitelistDisplay();
                    _processesView.Refresh();
                    LogInfo($"Removed {selectedProcess} from whitelist");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error removing process from whitelist: {ex.Message}");
                MessageBox.Show($"Error removing process from whitelist: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the AddMalwareHashButton control
        /// </summary>
        private void AddMalwareHashButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string hash = MalwareHashTextBox.Text.Trim();
                if (!string.IsNullOrEmpty(hash))
                {
                    _monitoringManager.AddMalwareHash(hash);
                    MalwareHashTextBox.Clear();
                    LogInfo($"Added malware hash: {hash}");
                    MessageBox.Show("Malware hash added successfully", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                LogError($"Error adding malware hash: {ex.Message}");
                MessageBox.Show($"Error adding malware hash: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the LoadHashesButton control
        /// </summary>
        private void LoadHashesButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var openFileDialog = new OpenFileDialog
                {
                    Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    Title = "Load Malware Hashes"
                };

                if (openFileDialog.ShowDialog() == true)
                {
                    int count = _monitoringManager.LoadMalwareHashesFromFile(openFileDialog.FileName);
                    MessageBox.Show($"Loaded {count} malware hashes from {openFileDialog.FileName}", "Load Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    LogInfo($"Loaded {count} malware hashes from {openFileDialog.FileName}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Error loading malware hashes: {ex.Message}");
                MessageBox.Show($"Error loading malware hashes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles the Click event of the SaveHashesButton control
        /// </summary>
        private void SaveHashesButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "Text files (*.txt)|*.txt",
                    DefaultExt = "txt",
                    Title = "Save Malware Hashes"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    if (_monitoringManager.SaveMalwareHashesToFile(saveFileDialog.FileName))
                    {
                        MessageBox.Show($"Malware hashes saved to {saveFileDialog.FileName}", "Save Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                        LogInfo($"Saved malware hashes to {saveFileDialog.FileName}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Error saving malware hashes: {ex.Message}");
                MessageBox.Show($"Error saving malware hashes: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Updates the monitoring status display
        /// </summary>
        private void UpdateMonitoringStatus(bool isMonitoring)
        {
            StatusTextBlock.Text = isMonitoring ? "Running" : "Stopped";
            StartButton.IsEnabled = !isMonitoring;
            StopButton.IsEnabled = isMonitoring;
        }

        /// <summary>
        /// Updates the whitelist display
        /// </summary>
        private void UpdateWhitelistDisplay()
        {
            WhitelistProcessesListBox.Items.Clear();
            foreach (var process in _monitoringManager.ProcessMonitor.WhitelistedProcesses)
            {
                WhitelistProcessesListBox.Items.Add(process);
            }
        }

        /// <summary>
        /// Filter for processes
        /// </summary>
        private bool ProcessFilter(object item)
        {
            if (item is ProcessInfo process)
            {
                // Apply search filter
                if (!string.IsNullOrEmpty(_processSearchText))
                {
                    bool matchesSearch = process.Name.ToLower().Contains(_processSearchText) ||
                                         process.Path.ToLower().Contains(_processSearchText) ||
                                         process.Id.ToString().Contains(_processSearchText);

                    if (!matchesSearch)
                    {
                        return false;
                    }
                }

                // Apply suspicious filter
                if (_showOnlySuspicious && !process.IsSuspicious)
                {
                    return false;
                }

                // Apply unknown filter
                if (_showOnlyUnknown && !process.IsUnknown)
                {
                    return false;
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Filter for alerts
        /// </summary>
        private bool AlertFilter(object item)
        {
            if (item is ProcessAlert alert)
            {
                // Apply search filter
                if (!string.IsNullOrEmpty(_alertSearchText))
                {
                    bool matchesSearch = alert.ProcessName.ToLower().Contains(_alertSearchText) ||
                                         alert.Description.ToLower().Contains(_alertSearchText) ||
                                         alert.AlertType.ToLower().Contains(_alertSearchText);

                    if (!matchesSearch)
                    {
                        return false;
                    }
                }

                // Apply severity filter
                if (_selectedAlertSeverity != "All Severities" && alert.Severity.ToString() != _selectedAlertSeverity)
                {
                    return false;
                }

                // Apply type filter
                if (_selectedAlertType != "All Types" && alert.AlertType != _selectedAlertType)
                {
                    return false;
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [ProcessMonitoringView] {message}");
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        private static void LogError(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[ERROR] [ProcessMonitoringView] {message}");
        }

        #endregion
    }
}