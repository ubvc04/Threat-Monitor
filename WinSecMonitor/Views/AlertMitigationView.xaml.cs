using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using WinSecMonitor.Modules.Alert;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for AlertMitigationView.xaml
    /// </summary>
    public partial class AlertMitigationView : UserControl, INotifyPropertyChanged
    {
        private AlertManager _alertManager;
        private MitigationEngine _mitigationEngine;
        private ObservableCollection<Alert> _alerts;
        private ObservableCollection<MitigationAction> _mitigationActions;
        private ObservableCollection<BlockedIP> _blockedIPs;
        private ObservableCollection<QuarantinedFile> _quarantinedFiles;
        private ObservableCollection<DisabledAccount> _disabledAccounts;
        private ObservableCollection<MitigationRule> _mitigationRules;
        private string _filterText;
        private string _mitigationFilterText;
        private Alert _selectedAlert;
        private bool _showAcknowledged;
        private string _selectedSeverityFilter;
        private string _selectedMitigationTypeFilter;
        private bool _isAutoMitigationEnabled;
        private int _alertRetentionDays;
        private int _maxAlertsToDisplay;
        private string _quarantineLocation;
        private int _quarantineRetentionDays;
        private string _selectedIPBlockingMethod;
        private int _defaultIPBlockDuration;
        private string _newIPToBlock;
        private string _newIPBlockReason;
        private string _newFileToQuarantine;
        private string _newFileQuarantineReason;

        // Commands
        public ICommand RefreshCommand { get; private set; }
        public ICommand AcknowledgeCommand { get; private set; }
        public ICommand AcknowledgeAllCommand { get; private set; }
        public ICommand ClearAcknowledgedCommand { get; private set; }
        public ICommand MitigateCommand { get; private set; }
        public ICommand ViewDetailsCommand { get; private set; }
        public ICommand ExportAlertsCommand { get; private set; }
        public ICommand OpenSettingsCommand { get; private set; }
        public ICommand ManageRulesCommand { get; private set; }
        public ICommand SaveSettingsCommand { get; private set; }
        public ICommand SaveQuarantineSettingsCommand { get; private set; }
        public ICommand SaveIPBlockingSettingsCommand { get; private set; }
        public ICommand AddRuleCommand { get; private set; }
        public ICommand RemoveRuleCommand { get; private set; }
        public ICommand EditRuleCommand { get; private set; }
        public ICommand BlockIPCommand { get; private set; }
        public ICommand UnblockIPCommand { get; private set; }
        public ICommand QuarantineFileCommand { get; private set; }
        public ICommand RestoreFileCommand { get; private set; }
        public ICommand DeleteQuarantinedFileCommand { get; private set; }
        public ICommand EnableAccountCommand { get; private set; }
        public ICommand RevertMitigationCommand { get; private set; }
        public ICommand BrowseQuarantineLocationCommand { get; private set; }

        public AlertMitigationView()
        {
            InitializeComponent();
            DataContext = this;

            // Initialize collections
            _alerts = new ObservableCollection<Alert>();
            _mitigationActions = new ObservableCollection<MitigationAction>();
            _blockedIPs = new ObservableCollection<BlockedIP>();
            _quarantinedFiles = new ObservableCollection<QuarantinedFile>();
            _disabledAccounts = new ObservableCollection<DisabledAccount>();
            _mitigationRules = new ObservableCollection<MitigationRule>();

            // Initialize properties
            _filterText = string.Empty;
            _mitigationFilterText = string.Empty;
            _showAcknowledged = false;
            _selectedSeverityFilter = "All";
            _selectedMitigationTypeFilter = "All";
            _isAutoMitigationEnabled = true;
            _alertRetentionDays = 30;
            _maxAlertsToDisplay = 1000;
            _quarantineLocation = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinSecMonitor\\Quarantine");
            _quarantineRetentionDays = 90;
            _selectedIPBlockingMethod = "Windows Firewall";
            _defaultIPBlockDuration = 24;

            // Initialize commands
            RefreshCommand = new RelayCommand(RefreshData);
            AcknowledgeCommand = new RelayCommand<Alert>(AcknowledgeAlert);
            AcknowledgeAllCommand = new RelayCommand(AcknowledgeAllAlerts);
            ClearAcknowledgedCommand = new RelayCommand(ClearAcknowledgedAlerts);
            MitigateCommand = new RelayCommand<Alert>(MitigateAlert);
            ViewDetailsCommand = new RelayCommand<Alert>(ViewAlertDetails);
            ExportAlertsCommand = new RelayCommand(ExportAlerts);
            OpenSettingsCommand = new RelayCommand(OpenSettings);
            ManageRulesCommand = new RelayCommand(ManageRules);
            SaveSettingsCommand = new RelayCommand(SaveSettings);
            SaveQuarantineSettingsCommand = new RelayCommand(SaveQuarantineSettings);
            SaveIPBlockingSettingsCommand = new RelayCommand(SaveIPBlockingSettings);
            AddRuleCommand = new RelayCommand(AddRule);
            RemoveRuleCommand = new RelayCommand(RemoveRule);
            EditRuleCommand = new RelayCommand<MitigationRule>(EditRule);
            BlockIPCommand = new RelayCommand(BlockIP);
            UnblockIPCommand = new RelayCommand<BlockedIP>(UnblockIP);
            QuarantineFileCommand = new RelayCommand(QuarantineFile);
            RestoreFileCommand = new RelayCommand<QuarantinedFile>(RestoreFile);
            DeleteQuarantinedFileCommand = new RelayCommand<QuarantinedFile>(DeleteQuarantinedFile);
            EnableAccountCommand = new RelayCommand<DisabledAccount>(EnableAccount);
            RevertMitigationCommand = new RelayCommand<MitigationAction>(RevertMitigation);
            BrowseQuarantineLocationCommand = new RelayCommand(BrowseQuarantineLocation);

            // Initialize managers
            InitializeManagers();

            // Load data
            LoadData();
        }

        private void InitializeManagers()
        {
            try
            {
                _alertManager = new AlertManager();
                _mitigationEngine = new MitigationEngine(_alertManager);

                // Subscribe to events
                _alertManager.AlertAdded += AlertManager_AlertAdded;
                _alertManager.AlertAcknowledged += AlertManager_AlertAcknowledged;
                _alertManager.AlertMitigated += AlertManager_AlertMitigated;
                _alertManager.Error += AlertManager_Error;

                _mitigationEngine.MitigationActionPerformed += MitigationEngine_MitigationActionPerformed;
                _mitigationEngine.MitigationRuleAdded += MitigationEngine_MitigationRuleAdded;
                _mitigationEngine.MitigationRuleRemoved += MitigationEngine_MitigationRuleRemoved;
                _mitigationEngine.MitigationRuleUpdated += MitigationEngine_MitigationRuleUpdated;
                _mitigationEngine.Error += MitigationEngine_Error;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing Alert & Mitigation components: {ex.Message}", "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadData()
        {
            try
            {
                // Load alerts
                var alerts = _alertManager.GetAlerts();
                _alerts.Clear();
                foreach (var alert in alerts)
                {
                    _alerts.Add(alert);
                }

                // Load mitigation actions
                var actions = _mitigationEngine.GetMitigationActions();
                _mitigationActions.Clear();
                foreach (var action in actions)
                {
                    _mitigationActions.Add(action);
                }

                // Load blocked IPs
                var blockedIPs = _mitigationEngine.GetBlockedIPs();
                _blockedIPs.Clear();
                foreach (var ip in blockedIPs)
                {
                    _blockedIPs.Add(ip);
                }

                // Load quarantined files
                var quarantinedFiles = _mitigationEngine.GetQuarantinedFiles();
                _quarantinedFiles.Clear();
                foreach (var file in quarantinedFiles)
                {
                    _quarantinedFiles.Add(file);
                }

                // Load disabled accounts
                var disabledAccounts = _mitigationEngine.GetDisabledAccounts();
                _disabledAccounts.Clear();
                foreach (var account in disabledAccounts)
                {
                    _disabledAccounts.Add(account);
                }

                // Load mitigation rules
                var rules = _mitigationEngine.GetMitigationRules();
                _mitigationRules.Clear();
                foreach (var rule in rules)
                {
                    _mitigationRules.Add(rule);
                }

                // Update statistics
                OnPropertyChanged(nameof(TotalAlerts));
                OnPropertyChanged(nameof(HighSeverityCount));
                OnPropertyChanged(nameof(MediumSeverityCount));
                OnPropertyChanged(nameof(LowSeverityCount));
                OnPropertyChanged(nameof(TotalMitigations));
                OnPropertyChanged(nameof(BlockedIPsCount));
                OnPropertyChanged(nameof(KilledProcessesCount));
                OnPropertyChanged(nameof(QuarantinedFilesCount));
                OnPropertyChanged(nameof(DisabledAccountsCount));
                OnPropertyChanged(nameof(ActiveRulesCount));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading data: {ex.Message}", "Data Loading Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #region Event Handlers

        private void AlertManager_AlertAdded(object sender, AlertEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _alerts.Insert(0, e.Alert);
                OnPropertyChanged(nameof(FilteredAlerts));
                OnPropertyChanged(nameof(TotalAlerts));
                OnPropertyChanged(nameof(HighSeverityCount));
                OnPropertyChanged(nameof(MediumSeverityCount));
                OnPropertyChanged(nameof(LowSeverityCount));
            });
        }

        private void AlertManager_AlertAcknowledged(object sender, AlertEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var alert = _alerts.FirstOrDefault(a => a.ID == e.Alert.ID);
                if (alert != null)
                {
                    int index = _alerts.IndexOf(alert);
                    _alerts[index] = e.Alert;
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            });
        }

        private void AlertManager_AlertMitigated(object sender, AlertEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var alert = _alerts.FirstOrDefault(a => a.ID == e.Alert.ID);
                if (alert != null)
                {
                    int index = _alerts.IndexOf(alert);
                    _alerts[index] = e.Alert;
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            });
        }

        private void AlertManager_Error(object sender, ErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show($"Alert Manager Error: {e.ErrorMessage}", "Alert Error", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }

        private void MitigationEngine_MitigationActionPerformed(object sender, MitigationActionEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _mitigationActions.Insert(0, e.Action);
                OnPropertyChanged(nameof(FilteredMitigationActions));
                OnPropertyChanged(nameof(TotalMitigations));

                // Update specific collections based on action type
                switch (e.Action.ActionType)
                {
                    case MitigationActionType.BlockIP:
                        RefreshBlockedIPs();
                        break;
                    case MitigationActionType.KillProcess:
                        OnPropertyChanged(nameof(KilledProcessesCount));
                        break;
                    case MitigationActionType.QuarantineFile:
                        RefreshQuarantinedFiles();
                        break;
                    case MitigationActionType.DisableUserAccount:
                        RefreshDisabledAccounts();
                        break;
                }
            });
        }

        private void MitigationEngine_MitigationRuleAdded(object sender, MitigationRuleEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _mitigationRules.Add(e.Rule);
                OnPropertyChanged(nameof(ActiveRulesCount));
            });
        }

        private void MitigationEngine_MitigationRuleRemoved(object sender, MitigationRuleEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var rule = _mitigationRules.FirstOrDefault(r => r.ID == e.Rule.ID);
                if (rule != null)
                {
                    _mitigationRules.Remove(rule);
                    OnPropertyChanged(nameof(ActiveRulesCount));
                }
            });
        }

        private void MitigationEngine_MitigationRuleUpdated(object sender, MitigationRuleEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var rule = _mitigationRules.FirstOrDefault(r => r.ID == e.Rule.ID);
                if (rule != null)
                {
                    int index = _mitigationRules.IndexOf(rule);
                    _mitigationRules[index] = e.Rule;
                    OnPropertyChanged(nameof(ActiveRulesCount));
                }
            });
        }

        private void MitigationEngine_Error(object sender, ErrorEventArgs e)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show($"Mitigation Engine Error: {e.ErrorMessage}", "Mitigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }

        #endregion

        #region Command Methods

        private void RefreshData(object parameter)
        {
            LoadData();
        }

        private void AcknowledgeAlert(Alert alert)
        {
            if (alert != null)
            {
                try
                {
                    _alertManager.AcknowledgeAlert(alert.ID);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error acknowledging alert: {ex.Message}", "Acknowledge Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void AcknowledgeAllAlerts(object parameter)
        {
            try
            {
                foreach (var alert in FilteredAlerts.Where(a => !a.IsAcknowledged))
                {
                    _alertManager.AcknowledgeAlert(alert.ID);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error acknowledging alerts: {ex.Message}", "Acknowledge Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearAcknowledgedAlerts(object parameter)
        {
            try
            {
                _alertManager.ClearAcknowledgedAlerts();
                LoadData();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error clearing acknowledged alerts: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void MitigateAlert(Alert alert)
        {
            if (alert != null)
            {
                try
                {
                    // Show mitigation options dialog
                    var mitigationWindow = new MitigationOptionsWindow(alert, _mitigationEngine);
                    mitigationWindow.Owner = Window.GetWindow(this);
                    mitigationWindow.ShowDialog();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error showing mitigation options: {ex.Message}", "Mitigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ViewAlertDetails(Alert alert)
        {
            if (alert != null)
            {
                try
                {
                    // Show alert details dialog
                    var detailsWindow = new AlertDetailsWindow(alert);
                    detailsWindow.Owner = Window.GetWindow(this);
                    detailsWindow.ShowDialog();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error showing alert details: {ex.Message}", "Details Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportAlerts(object parameter)
        {
            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                    DefaultExt = "csv",
                    Title = "Export Alerts"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    _alertManager.ExportAlertsToCSV(saveFileDialog.FileName, FilteredAlerts.ToList());
                    MessageBox.Show("Alerts exported successfully.", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error exporting alerts: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OpenSettings(object parameter)
        {
            // Navigate to Settings tab
            var tabControl = FindVisualChild<TabControl>(this);
            if (tabControl != null)
            {
                tabControl.SelectedIndex = 2; // Settings tab
            }
        }

        private void ManageRules(object parameter)
        {
            // Navigate to Settings tab and expand Mitigation Rules
            var tabControl = FindVisualChild<TabControl>(this);
            if (tabControl != null)
            {
                tabControl.SelectedIndex = 2; // Settings tab
                
                // Find and expand the Mitigation Rules expander
                var expanders = FindVisualChildren<Expander>(this);
                foreach (var expander in expanders)
                {
                    if (expander.Header.ToString() == "Mitigation Rules")
                    {
                        expander.IsExpanded = true;
                        break;
                    }
                }
            }
        }

        private void SaveSettings(object parameter)
        {
            try
            {
                // Save general settings
                _mitigationEngine.SetAutoMitigationEnabled(IsAutoMitigationEnabled);
                _alertManager.SetAlertRetentionDays(AlertRetentionDays);
                
                MessageBox.Show("Settings saved successfully.", "Settings Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving settings: {ex.Message}", "Settings Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveQuarantineSettings(object parameter)
        {
            try
            {
                // Save quarantine settings
                _mitigationEngine.SetQuarantineLocation(QuarantineLocation);
                _mitigationEngine.SetQuarantineRetentionDays(QuarantineRetentionDays);
                
                MessageBox.Show("Quarantine settings saved successfully.", "Settings Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving quarantine settings: {ex.Message}", "Settings Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveIPBlockingSettings(object parameter)
        {
            try
            {
                // Save IP blocking settings
                _mitigationEngine.SetIPBlockingMethod(SelectedIPBlockingMethod);
                _mitigationEngine.SetDefaultIPBlockDuration(DefaultIPBlockDuration);
                
                MessageBox.Show("IP blocking settings saved successfully.", "Settings Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving IP blocking settings: {ex.Message}", "Settings Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddRule(object parameter)
        {
            try
            {
                // Show add rule dialog
                var ruleWindow = new MitigationRuleWindow(null, _mitigationEngine);
                ruleWindow.Owner = Window.GetWindow(this);
                ruleWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error adding rule: {ex.Message}", "Rule Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RemoveRule(object parameter)
        {
            try
            {
                // Get selected rule from DataGrid
                var dataGrid = FindVisualChild<DataGrid>(this, d => d.Name == "RulesDataGrid");
                if (dataGrid != null && dataGrid.SelectedItem is MitigationRule rule)
                {
                    var result = MessageBox.Show($"Are you sure you want to remove the rule '{rule.Name}'?", "Confirm Remove", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.RemoveMitigationRule(rule.ID);
                    }
                }
                else
                {
                    MessageBox.Show("Please select a rule to remove.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error removing rule: {ex.Message}", "Rule Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void EditRule(MitigationRule rule)
        {
            if (rule != null)
            {
                try
                {
                    // Show edit rule dialog
                    var ruleWindow = new MitigationRuleWindow(rule, _mitigationEngine);
                    ruleWindow.Owner = Window.GetWindow(this);
                    ruleWindow.ShowDialog();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error editing rule: {ex.Message}", "Rule Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BlockIP(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(NewIPToBlock))
                {
                    MessageBox.Show("Please enter an IP address to block.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string reason = string.IsNullOrWhiteSpace(NewIPBlockReason) ? "Manually blocked" : NewIPBlockReason;
                
                _mitigationEngine.BlockIPAsync(NewIPToBlock, reason);
                
                // Clear input fields
                NewIPToBlock = string.Empty;
                NewIPBlockReason = string.Empty;
                OnPropertyChanged(nameof(NewIPToBlock));
                OnPropertyChanged(nameof(NewIPBlockReason));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error blocking IP: {ex.Message}", "Block IP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UnblockIP(BlockedIP blockedIP)
        {
            if (blockedIP != null)
            {
                try
                {
                    var result = MessageBox.Show($"Are you sure you want to unblock the IP '{blockedIP.IPAddress}'?", "Confirm Unblock", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.UnblockIPAsync(blockedIP.IPAddress);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error unblocking IP: {ex.Message}", "Unblock IP Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void QuarantineFile(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(NewFileToQuarantine))
                {
                    MessageBox.Show("Please enter a file path to quarantine.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string reason = string.IsNullOrWhiteSpace(NewFileQuarantineReason) ? "Manually quarantined" : NewFileQuarantineReason;
                
                _mitigationEngine.QuarantineFile(NewFileToQuarantine, reason);
                
                // Clear input fields
                NewFileToQuarantine = string.Empty;
                NewFileQuarantineReason = string.Empty;
                OnPropertyChanged(nameof(NewFileToQuarantine));
                OnPropertyChanged(nameof(NewFileQuarantineReason));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error quarantining file: {ex.Message}", "Quarantine Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RestoreFile(QuarantinedFile quarantinedFile)
        {
            if (quarantinedFile != null)
            {
                try
                {
                    var result = MessageBox.Show($"Are you sure you want to restore the file '{quarantinedFile.OriginalPath}'? This may restore potentially malicious content.", "Confirm Restore", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.RestoreQuarantinedFile(quarantinedFile.ID);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error restoring file: {ex.Message}", "Restore Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void DeleteQuarantinedFile(QuarantinedFile quarantinedFile)
        {
            if (quarantinedFile != null)
            {
                try
                {
                    var result = MessageBox.Show($"Are you sure you want to permanently delete the quarantined file '{quarantinedFile.OriginalPath}'? This action cannot be undone.", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.DeleteQuarantinedFile(quarantinedFile.ID);
                        RefreshQuarantinedFiles();
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error deleting file: {ex.Message}", "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void EnableAccount(DisabledAccount disabledAccount)
        {
            if (disabledAccount != null)
            {
                try
                {
                    var result = MessageBox.Show($"Are you sure you want to enable the account '{disabledAccount.Username}'?", "Confirm Enable", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.EnableUserAccountAsync(disabledAccount.Username);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error enabling account: {ex.Message}", "Enable Account Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void RevertMitigation(MitigationAction mitigationAction)
        {
            if (mitigationAction != null && mitigationAction.CanRevert)
            {
                try
                {
                    var result = MessageBox.Show($"Are you sure you want to revert this mitigation action?", "Confirm Revert", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        _mitigationEngine.RevertMitigationAction(mitigationAction.ID);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error reverting mitigation: {ex.Message}", "Revert Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BrowseQuarantineLocation(object parameter)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select Quarantine Location",
                ShowNewFolderButton = true
            };

            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                QuarantineLocation = dialog.SelectedPath;
            }
        }

        #endregion

        #region Helper Methods

        private void RefreshBlockedIPs()
        {
            var blockedIPs = _mitigationEngine.GetBlockedIPs();
            _blockedIPs.Clear();
            foreach (var ip in blockedIPs)
            {
                _blockedIPs.Add(ip);
            }
            OnPropertyChanged(nameof(BlockedIPsCount));
        }

        private void RefreshQuarantinedFiles()
        {
            var quarantinedFiles = _mitigationEngine.GetQuarantinedFiles();
            _quarantinedFiles.Clear();
            foreach (var file in quarantinedFiles)
            {
                _quarantinedFiles.Add(file);
            }
            OnPropertyChanged(nameof(QuarantinedFilesCount));
        }

        private void RefreshDisabledAccounts()
        {
            var disabledAccounts = _mitigationEngine.GetDisabledAccounts();
            _disabledAccounts.Clear();
            foreach (var account in disabledAccounts)
            {
                _disabledAccounts.Add(account);
            }
            OnPropertyChanged(nameof(DisabledAccountsCount));
        }

        private static T FindVisualChild<T>(DependencyObject parent, Func<T, bool> condition = null) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild && (condition == null || condition(typedChild)))
                {
                    return typedChild;
                }

                var result = FindVisualChild(child, condition);
                if (result != null)
                {
                    return result;
                }
            }
            return null;
        }

        private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild)
                {
                    yield return typedChild;
                }

                foreach (var grandChild in FindVisualChildren<T>(child))
                {
                    yield return grandChild;
                }
            }
        }

        #endregion

        #region Properties

        public ObservableCollection<Alert> Alerts => _alerts;

        public IEnumerable<Alert> FilteredAlerts
        {
            get
            {
                var query = _alerts.AsEnumerable();

                // Filter by acknowledgment status
                if (!ShowAcknowledged)
                {
                    query = query.Where(a => !a.IsAcknowledged);
                }

                // Filter by severity
                if (!string.IsNullOrEmpty(SelectedSeverityFilter) && SelectedSeverityFilter != "All")
                {
                    AlertSeverity severity = (AlertSeverity)Enum.Parse(typeof(AlertSeverity), SelectedSeverityFilter);
                    query = query.Where(a => a.Severity == severity);
                }

                // Filter by text
                if (!string.IsNullOrEmpty(FilterText))
                {
                    string filter = FilterText.ToLower();
                    query = query.Where(a =>
                        a.Title.ToLower().Contains(filter) ||
                        a.Description.ToLower().Contains(filter) ||
                        a.Source.ToLower().Contains(filter));
                }

                // Limit the number of alerts to display
                return query.Take(MaxAlertsToDisplay);
            }
        }

        public IEnumerable<MitigationAction> FilteredMitigationActions
        {
            get
            {
                var query = _mitigationActions.AsEnumerable();

                // Filter by type
                if (!string.IsNullOrEmpty(SelectedMitigationTypeFilter) && SelectedMitigationTypeFilter != "All")
                {
                    MitigationActionType actionType = (MitigationActionType)Enum.Parse(typeof(MitigationActionType), SelectedMitigationTypeFilter);
                    query = query.Where(a => a.ActionType == actionType);
                }

                // Filter by text
                if (!string.IsNullOrEmpty(MitigationFilterText))
                {
                    string filter = MitigationFilterText.ToLower();
                    query = query.Where(a =>
                        a.Target.ToLower().Contains(filter) ||
                        a.Details.ToLower().Contains(filter));
                }

                return query;
            }
        }

        public ObservableCollection<BlockedIP> BlockedIPs => _blockedIPs;

        public ObservableCollection<QuarantinedFile> QuarantinedFiles => _quarantinedFiles;

        public ObservableCollection<DisabledAccount> DisabledAccounts => _disabledAccounts;

        public ObservableCollection<MitigationRule> MitigationRules => _mitigationRules;

        public string FilterText
        {
            get => _filterText;
            set
            {
                if (_filterText != value)
                {
                    _filterText = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            }
        }

        public string MitigationFilterText
        {
            get => _mitigationFilterText;
            set
            {
                if (_mitigationFilterText != value)
                {
                    _mitigationFilterText = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredMitigationActions));
                }
            }
        }

        public Alert SelectedAlert
        {
            get => _selectedAlert;
            set
            {
                if (_selectedAlert != value)
                {
                    _selectedAlert = value;
                    OnPropertyChanged();
                }
            }
        }

        public bool ShowAcknowledged
        {
            get => _showAcknowledged;
            set
            {
                if (_showAcknowledged != value)
                {
                    _showAcknowledged = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            }
        }

        public string SelectedSeverityFilter
        {
            get => _selectedSeverityFilter;
            set
            {
                if (_selectedSeverityFilter != value)
                {
                    _selectedSeverityFilter = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            }
        }

        public string SelectedMitigationTypeFilter
        {
            get => _selectedMitigationTypeFilter;
            set
            {
                if (_selectedMitigationTypeFilter != value)
                {
                    _selectedMitigationTypeFilter = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredMitigationActions));
                }
            }
        }

        public bool IsAutoMitigationEnabled
        {
            get => _isAutoMitigationEnabled;
            set
            {
                if (_isAutoMitigationEnabled != value)
                {
                    _isAutoMitigationEnabled = value;
                    OnPropertyChanged();
                }
            }
        }

        public int AlertRetentionDays
        {
            get => _alertRetentionDays;
            set
            {
                if (_alertRetentionDays != value)
                {
                    _alertRetentionDays = value;
                    OnPropertyChanged();
                }
            }
        }

        public int MaxAlertsToDisplay
        {
            get => _maxAlertsToDisplay;
            set
            {
                if (_maxAlertsToDisplay != value)
                {
                    _maxAlertsToDisplay = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(FilteredAlerts));
                }
            }
        }

        public string QuarantineLocation
        {
            get => _quarantineLocation;
            set
            {
                if (_quarantineLocation != value)
                {
                    _quarantineLocation = value;
                    OnPropertyChanged();
                }
            }
        }

        public int QuarantineRetentionDays
        {
            get => _quarantineRetentionDays;
            set
            {
                if (_quarantineRetentionDays != value)
                {
                    _quarantineRetentionDays = value;
                    OnPropertyChanged();
                }
            }
        }

        public string SelectedIPBlockingMethod
        {
            get => _selectedIPBlockingMethod;
            set
            {
                if (_selectedIPBlockingMethod != value)
                {
                    _selectedIPBlockingMethod = value;
                    OnPropertyChanged();
                }
            }
        }

        public int DefaultIPBlockDuration
        {
            get => _defaultIPBlockDuration;
            set
            {
                if (_defaultIPBlockDuration != value)
                {
                    _defaultIPBlockDuration = value;
                    OnPropertyChanged();
                }
            }
        }

        public string NewIPToBlock
        {
            get => _newIPToBlock;
            set
            {
                if (_newIPToBlock != value)
                {
                    _newIPToBlock = value;
                    OnPropertyChanged();
                }
            }
        }

        public string NewIPBlockReason
        {
            get => _newIPBlockReason;
            set
            {
                if (_newIPBlockReason != value)
                {
                    _newIPBlockReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public string NewFileToQuarantine
        {
            get => _newFileToQuarantine;
            set
            {
                if (_newFileToQuarantine != value)
                {
                    _newFileToQuarantine = value;
                    OnPropertyChanged();
                }
            }
        }

        public string NewFileQuarantineReason
        {
            get => _newFileQuarantineReason;
            set
            {
                if (_newFileQuarantineReason != value)
                {
                    _newFileQuarantineReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public IEnumerable<string> SeverityFilters => new[] { "All", "High", "Medium", "Low" };

        public IEnumerable<string> MitigationTypeFilters => new[] { "All", "BlockIP", "KillProcess", "QuarantineFile", "DisableUserAccount" };

        public IEnumerable<string> IPBlockingMethods => new[] { "Windows Firewall", "IPTables", "Custom" };

        // Statistics properties
        public int TotalAlerts => _alerts.Count;
        public int HighSeverityCount => _alerts.Count(a => a.Severity == AlertSeverity.High);
        public int MediumSeverityCount => _alerts.Count(a => a.Severity == AlertSeverity.Medium);
        public int LowSeverityCount => _alerts.Count(a => a.Severity == AlertSeverity.Low);
        public int TotalMitigations => _mitigationActions.Count;
        public int BlockedIPsCount => _blockedIPs.Count;
        public int KilledProcessesCount => _mitigationActions.Count(a => a.ActionType == MitigationActionType.KillProcess);
        public int QuarantinedFilesCount => _quarantinedFiles.Count;
        public int DisabledAccountsCount => _disabledAccounts.Count;
        public int ActiveRulesCount => _mitigationRules.Count(r => r.IsEnabled);

        #endregion

        #region INotifyPropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    // Helper class for commands
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Predicate<object> _canExecute;

        public RelayCommand(Action execute) : this(p => execute(), null)
        {
        }

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

    // Generic version of RelayCommand
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