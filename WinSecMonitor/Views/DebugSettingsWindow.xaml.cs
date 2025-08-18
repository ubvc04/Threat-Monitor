using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using WinSecMonitor.Commands;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Views
{
    public partial class DebugSettingsWindow : Window, INotifyPropertyChanged
    {
        private bool _debugModeEnabled;
        private int _maxLogFileSizeMB;
        private int _maxLogFiles;
        private int _logBufferSize;
        
        public event PropertyChangedEventHandler PropertyChanged;
        
        public DebugSettingsWindow()
        {
            InitializeComponent();
            DataContext = this;
            
            // Initialize from current Logger settings
            _debugModeEnabled = Logger.Instance.DebugModeEnabled;
            _maxLogFileSizeMB = Logger.Instance.MaxLogFileSizeBytes / (1024 * 1024);
            _maxLogFiles = Logger.Instance.MaxLogFiles;
            
            // Get buffer size using reflection since it's private
            var bufferField = typeof(Logger).GetField("_bufferSize", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (bufferField != null)
            {
                _logBufferSize = (int)bufferField.GetValue(Logger.Instance);
            }
            else
            {
                _logBufferSize = 100; // Default
            }
            
            // Initialize commands
            SaveCommand = new RelayCommand(Save);
            CancelCommand = new RelayCommand(Cancel);
            OpenLogDirectoryCommand = new RelayCommand(OpenLogDirectory);
        }
        
        public bool DebugModeEnabled
        {
            get => _debugModeEnabled;
            set
            {
                if (_debugModeEnabled != value)
                {
                    _debugModeEnabled = value;
                    OnPropertyChanged(nameof(DebugModeEnabled));
                }
            }
        }
        
        public int MaxLogFileSizeMB
        {
            get => _maxLogFileSizeMB;
            set
            {
                if (_maxLogFileSizeMB != value)
                {
                    _maxLogFileSizeMB = value;
                    OnPropertyChanged(nameof(MaxLogFileSizeMB));
                }
            }
        }
        
        public int MaxLogFiles
        {
            get => _maxLogFiles;
            set
            {
                if (_maxLogFiles != value)
                {
                    _maxLogFiles = value;
                    OnPropertyChanged(nameof(MaxLogFiles));
                }
            }
        }
        
        public int LogBufferSize
        {
            get => _logBufferSize;
            set
            {
                if (_logBufferSize != value)
                {
                    _logBufferSize = value;
                    OnPropertyChanged(nameof(LogBufferSize));
                }
            }
        }
        
        public ICommand SaveCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand OpenLogDirectoryCommand { get; }
        
        private void Save()
        {
            try
            {
                // Validate input
                if (MaxLogFileSizeMB < 1)
                {
                    MessageBox.Show("Maximum log file size must be at least 1 MB", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (MaxLogFiles < 1)
                {
                    MessageBox.Show("Maximum number of log files must be at least 1", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (LogBufferSize < 1)
                {
                    MessageBox.Show("Log buffer size must be at least 1", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                // Apply settings to Logger
                Logger.Instance.DebugModeEnabled = DebugModeEnabled;
                Logger.Instance.MaxLogFileSizeBytes = MaxLogFileSizeMB * 1024 * 1024;
                Logger.Instance.MaxLogFiles = MaxLogFiles;
                
                // Set buffer size using reflection since it's private
                var bufferField = typeof(Logger).GetField("_bufferSize", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (bufferField != null)
                {
                    bufferField.SetValue(Logger.Instance, LogBufferSize);
                }
                
                // Log the changes
                Logger.Instance.LogInformation("Debug settings updated");
                
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving debug settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void Cancel()
        {
            DialogResult = false;
            Close();
        }
        
        private void OpenLogDirectory()
        {
            try
            {
                string logsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WinSecMonitor",
                    "Logs");
                    
                if (Directory.Exists(logsPath))
                {
                    Process.Start("explorer.exe", logsPath);
                }
                else
                {
                    MessageBox.Show("Log directory does not exist yet", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening log directory: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}