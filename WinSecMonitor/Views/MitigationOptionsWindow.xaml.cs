using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using WinSecMonitor.Modules.Alert;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for MitigationOptionsWindow.xaml
    /// </summary>
    public partial class MitigationOptionsWindow : Window, INotifyPropertyChanged
    {
        private readonly Alert _alert;
        private readonly MitigationEngine _mitigationEngine;
        private bool _applyAutomaticMitigation;
        private string _ipToBlock;
        private int _ipBlockDuration;
        private string _ipBlockReason;
        private string _processID;
        private string _processKillReason;
        private string _fileToQuarantine;
        private string _fileQuarantineReason;
        private string _usernameToDisable;
        private string _accountDisableReason;
        private string _customMitigationDetails;

        public MitigationOptionsWindow(Alert alert, MitigationEngine mitigationEngine)
        {
            InitializeComponent();
            DataContext = this;

            _alert = alert ?? throw new ArgumentNullException(nameof(alert));
            _mitigationEngine = mitigationEngine ?? throw new ArgumentNullException(nameof(mitigationEngine));

            // Initialize properties
            _applyAutomaticMitigation = true;
            _ipBlockDuration = 24; // Default 24 hours

            // Initialize commands
            BlockIPCommand = new RelayCommand(BlockIP, CanBlockIP);
            KillProcessCommand = new RelayCommand(KillProcess, CanKillProcess);
            QuarantineFileCommand = new RelayCommand(QuarantineFile, CanQuarantineFile);
            DisableAccountCommand = new RelayCommand(DisableAccount, CanDisableAccount);
            ApplyCustomMitigationCommand = new RelayCommand(ApplyCustomMitigation, CanApplyCustomMitigation);

            // Pre-populate fields based on alert type and data
            PopulateFieldsFromAlert();
        }

        private void PopulateFieldsFromAlert()
        {
            // Extract potential mitigation targets from the alert
            if (_alert.AdditionalData != null)
            {
                // Try to extract IP address
                if (_alert.AdditionalData.TryGetValue("IPAddress", out var ipObj) && ipObj is string ip)
                {
                    IPToBlock = ip;
                }
                else if (_alert.AdditionalData.TryGetValue("SourceIP", out ipObj) && ipObj is string sourceIp)
                {
                    IPToBlock = sourceIp;
                }
                else if (_alert.AdditionalData.TryGetValue("DestinationIP", out ipObj) && ipObj is string destIp)
                {
                    IPToBlock = destIp;
                }

                // Try to extract process information
                if (_alert.AdditionalData.TryGetValue("ProcessID", out var pidObj) && pidObj != null)
                {
                    ProcessID = pidObj.ToString();
                }

                // Try to extract file path
                if (_alert.AdditionalData.TryGetValue("FilePath", out var fileObj) && fileObj is string file)
                {
                    FileToQuarantine = file;
                }

                // Try to extract username
                if (_alert.AdditionalData.TryGetValue("Username", out var userObj) && userObj is string user)
                {
                    UsernameToDisable = user;
                }
            }

            // Set default reasons based on alert
            string defaultReason = $"Response to alert: {_alert.Title}";
            IPBlockReason = defaultReason;
            ProcessKillReason = defaultReason;
            FileQuarantineReason = defaultReason;
            AccountDisableReason = defaultReason;
        }

        #region Properties

        public string AlertTitle => _alert.Title;

        public string AlertDescription => _alert.Description;

        public bool ApplyAutomaticMitigation
        {
            get => _applyAutomaticMitigation;
            set
            {
                if (_applyAutomaticMitigation != value)
                {
                    _applyAutomaticMitigation = value;
                    OnPropertyChanged();
                }
            }
        }

        public string AutomaticMitigationDescription
        {
            get
            {
                var applicableRules = _mitigationEngine.GetApplicableRulesForAlert(_alert);
                if (applicableRules.Count == 0)
                {
                    return "No automatic mitigation rules apply to this alert.";
                }
                else
                {
                    return $"{applicableRules.Count} mitigation rule(s) will be applied automatically.";
                }
            }
        }

        public string IPToBlock
        {
            get => _ipToBlock;
            set
            {
                if (_ipToBlock != value)
                {
                    _ipToBlock = value;
                    OnPropertyChanged();
                }
            }
        }

        public int IPBlockDuration
        {
            get => _ipBlockDuration;
            set
            {
                if (_ipBlockDuration != value)
                {
                    _ipBlockDuration = value;
                    OnPropertyChanged();
                }
            }
        }

        public string IPBlockReason
        {
            get => _ipBlockReason;
            set
            {
                if (_ipBlockReason != value)
                {
                    _ipBlockReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public string ProcessID
        {
            get => _processID;
            set
            {
                if (_processID != value)
                {
                    _processID = value;
                    OnPropertyChanged();
                }
            }
        }

        public string ProcessKillReason
        {
            get => _processKillReason;
            set
            {
                if (_processKillReason != value)
                {
                    _processKillReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public string FileToQuarantine
        {
            get => _fileToQuarantine;
            set
            {
                if (_fileToQuarantine != value)
                {
                    _fileToQuarantine = value;
                    OnPropertyChanged();
                }
            }
        }

        public string FileQuarantineReason
        {
            get => _fileQuarantineReason;
            set
            {
                if (_fileQuarantineReason != value)
                {
                    _fileQuarantineReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public string UsernameToDisable
        {
            get => _usernameToDisable;
            set
            {
                if (_usernameToDisable != value)
                {
                    _usernameToDisable = value;
                    OnPropertyChanged();
                }
            }
        }

        public string AccountDisableReason
        {
            get => _accountDisableReason;
            set
            {
                if (_accountDisableReason != value)
                {
                    _accountDisableReason = value;
                    OnPropertyChanged();
                }
            }
        }

        public string CustomMitigationDetails
        {
            get => _customMitigationDetails;
            set
            {
                if (_customMitigationDetails != value)
                {
                    _customMitigationDetails = value;
                    OnPropertyChanged();
                }
            }
        }

        public ICommand BlockIPCommand { get; }
        public ICommand KillProcessCommand { get; }
        public ICommand QuarantineFileCommand { get; }
        public ICommand DisableAccountCommand { get; }
        public ICommand ApplyCustomMitigationCommand { get; }

        #endregion

        #region Command Methods

        private void BlockIP(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(IPToBlock))
                {
                    MessageBox.Show("Please enter an IP address to block.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _mitigationEngine.BlockIPAsync(IPToBlock, IPBlockReason, IPBlockDuration, _alert.ID);
                MessageBox.Show($"IP {IPToBlock} has been blocked for {IPBlockDuration} hours.", "IP Blocked", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error blocking IP: {ex.Message}", "Block IP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanBlockIP(object parameter)
        {
            return !string.IsNullOrWhiteSpace(IPToBlock);
        }

        private void KillProcess(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ProcessID) || !int.TryParse(ProcessID, out int pid))
                {
                    MessageBox.Show("Please enter a valid process ID.", "Invalid Process ID", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _mitigationEngine.KillProcess(pid, ProcessKillReason, _alert.ID);
                MessageBox.Show($"Process with ID {pid} has been terminated.", "Process Terminated", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error killing process: {ex.Message}", "Process Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanKillProcess(object parameter)
        {
            return !string.IsNullOrWhiteSpace(ProcessID) && int.TryParse(ProcessID, out _);
        }

        private void QuarantineFile(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(FileToQuarantine))
                {
                    MessageBox.Show("Please enter a file path to quarantine.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _mitigationEngine.QuarantineFile(FileToQuarantine, FileQuarantineReason, _alert.ID);
                MessageBox.Show($"File {FileToQuarantine} has been quarantined.", "File Quarantined", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error quarantining file: {ex.Message}", "Quarantine Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanQuarantineFile(object parameter)
        {
            return !string.IsNullOrWhiteSpace(FileToQuarantine);
        }

        private void DisableAccount(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(UsernameToDisable))
                {
                    MessageBox.Show("Please enter a username to disable.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = MessageBox.Show($"Are you sure you want to disable the account '{UsernameToDisable}'? This is a significant action that may impact system access.", 
                    "Confirm Account Disable", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    _mitigationEngine.DisableUserAccountAsync(UsernameToDisable, AccountDisableReason, _alert.ID);
                    MessageBox.Show($"User account {UsernameToDisable} has been disabled.", "Account Disabled", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error disabling account: {ex.Message}", "Account Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanDisableAccount(object parameter)
        {
            return !string.IsNullOrWhiteSpace(UsernameToDisable);
        }

        private void ApplyCustomMitigation(object parameter)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(CustomMitigationDetails))
                {
                    MessageBox.Show("Please enter custom mitigation details.", "Missing Information", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Update the alert with custom mitigation details
                _mitigationEngine.ApplyCustomMitigation(_alert.ID, CustomMitigationDetails);
                MessageBox.Show("Custom mitigation has been applied.", "Mitigation Applied", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error applying custom mitigation: {ex.Message}", "Mitigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanApplyCustomMitigation(object parameter)
        {
            return !string.IsNullOrWhiteSpace(CustomMitigationDetails);
        }

        #endregion

        #region INotifyPropertyChanged

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}