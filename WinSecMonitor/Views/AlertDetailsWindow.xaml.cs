using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using WinSecMonitor.Modules.Alert;

namespace WinSecMonitor.Views
{
    /// <summary>
    /// Interaction logic for AlertDetailsWindow.xaml
    /// </summary>
    public partial class AlertDetailsWindow : Window, INotifyPropertyChanged
    {
        private readonly Alert _alert;
        private readonly AlertManager _alertManager;
        private readonly MitigationEngine _mitigationEngine;

        public AlertDetailsWindow(Alert alert, AlertManager alertManager = null, MitigationEngine mitigationEngine = null)
        {
            InitializeComponent();
            DataContext = this;

            _alert = alert ?? throw new ArgumentNullException(nameof(alert));
            _alertManager = alertManager;
            _mitigationEngine = mitigationEngine;

            // Initialize commands
            AcknowledgeCommand = new RelayCommand(AcknowledgeAlert, CanAcknowledgeAlert);
            MitigateCommand = new RelayCommand(MitigateAlert, CanMitigateAlert);

            // Parse additional data
            if (_alert.AdditionalData != null)
            {
                AdditionalDataItems = new ObservableCollection<KeyValuePair<string, string>>(
                    _alert.AdditionalData.Select(kvp => new KeyValuePair<string, string>(kvp.Key, kvp.Value?.ToString() ?? "<null>"))
                );
            }
            else
            {
                AdditionalDataItems = new ObservableCollection<KeyValuePair<string, string>>();
            }
        }

        #region Properties

        public string AlertID => $"Alert ID: {_alert.ID}";

        public string Title => _alert.Title;

        public string Description => _alert.Description;

        public string Severity => _alert.Severity.ToString();

        public Brush SeverityBrush
        {
            get
            {
                return _alert.Severity switch
                {
                    AlertSeverity.High => new SolidColorBrush(Colors.Red),
                    AlertSeverity.Medium => new SolidColorBrush(Colors.Orange),
                    AlertSeverity.Low => new SolidColorBrush(Colors.Green),
                    _ => new SolidColorBrush(Colors.Gray)
                };
            }
        }

        public string Source => _alert.Source;

        public string Type => _alert.Type.ToString();

        public string Timestamp => _alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");

        public string AcknowledgmentStatus => _alert.IsAcknowledged 
            ? $"Acknowledged on {_alert.AcknowledgedTimestamp?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Unknown"}" 
            : "Not Acknowledged";

        public string MitigationStatus => _alert.IsMitigated 
            ? $"Mitigated on {_alert.MitigationTimestamp?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Unknown"}" 
            : "Not Mitigated";

        public string MitigationDetails => _alert.MitigationDetails;

        public Visibility MitigationDetailsVisibility => 
            !string.IsNullOrEmpty(_alert.MitigationDetails) ? Visibility.Visible : Visibility.Collapsed;

        public Visibility AcknowledgeButtonVisibility => 
            !_alert.IsAcknowledged && _alertManager != null ? Visibility.Visible : Visibility.Collapsed;

        public Visibility MitigateButtonVisibility => 
            !_alert.IsMitigated && _mitigationEngine != null ? Visibility.Visible : Visibility.Collapsed;

        public ObservableCollection<KeyValuePair<string, string>> AdditionalDataItems { get; }

        public ICommand AcknowledgeCommand { get; }

        public ICommand MitigateCommand { get; }

        #endregion

        #region Command Methods

        private void AcknowledgeAlert(object parameter)
        {
            try
            {
                _alertManager?.AcknowledgeAlert(_alert.ID);
                OnPropertyChanged(nameof(AcknowledgmentStatus));
                OnPropertyChanged(nameof(AcknowledgeButtonVisibility));
                MessageBox.Show("Alert has been acknowledged.", "Alert Acknowledged", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error acknowledging alert: {ex.Message}", "Acknowledge Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanAcknowledgeAlert(object parameter)
        {
            return !_alert.IsAcknowledged && _alertManager != null;
        }

        private void MitigateAlert(object parameter)
        {
            try
            {
                // Open mitigation options window
                var mitigationWindow = new MitigationOptionsWindow(_alert, _mitigationEngine);
                mitigationWindow.Owner = this;
                mitigationWindow.ShowDialog();

                // Refresh properties after mitigation
                OnPropertyChanged(nameof(MitigationStatus));
                OnPropertyChanged(nameof(MitigationDetails));
                OnPropertyChanged(nameof(MitigationDetailsVisibility));
                OnPropertyChanged(nameof(MitigateButtonVisibility));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error showing mitigation options: {ex.Message}", "Mitigation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private bool CanMitigateAlert(object parameter)
        {
            return !_alert.IsMitigated && _mitigationEngine != null;
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