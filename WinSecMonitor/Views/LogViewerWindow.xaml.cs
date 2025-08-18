using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using WinSecMonitor.Commands;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Views
{
    public partial class LogViewerWindow : Window, INotifyPropertyChanged
    {
        private string _filterText = "";
        private string _selectedLogLevel = "All";
        private DateTime? _selectedDate = DateTime.Today;
        private string _statusText = "Ready";
        private ObservableCollection<LogEntry> _allLogEntries = new ObservableCollection<LogEntry>();
        private ObservableCollection<LogEntry> _filteredLogEntries = new ObservableCollection<LogEntry>();
        
        public event PropertyChangedEventHandler PropertyChanged;
        
        public LogViewerWindow()
        {
            InitializeComponent();
            DataContext = this;
            
            // Initialize commands
            RefreshCommand = new RelayCommand(RefreshLogs);
            ExportCommand = new RelayCommand(ExportLogs);
            ClearLogsCommand = new RelayCommand(ClearLogs);
            
            // Load logs
            RefreshLogs();
        }
        
        public string FilterText
        {
            get => _filterText;
            set
            {
                if (_filterText != value)
                {
                    _filterText = value;
                    OnPropertyChanged(nameof(FilterText));
                    ApplyFilters();
                }
            }
        }
        
        public string SelectedLogLevel
        {
            get => _selectedLogLevel;
            set
            {
                if (_selectedLogLevel != value)
                {
                    _selectedLogLevel = value;
                    OnPropertyChanged(nameof(SelectedLogLevel));
                    ApplyFilters();
                }
            }
        }
        
        public DateTime? SelectedDate
        {
            get => _selectedDate;
            set
            {
                if (_selectedDate != value)
                {
                    _selectedDate = value;
                    OnPropertyChanged(nameof(SelectedDate));
                    ApplyFilters();
                }
            }
        }
        
        public string StatusText
        {
            get => _statusText;
            set
            {
                if (_statusText != value)
                {
                    _statusText = value;
                    OnPropertyChanged(nameof(StatusText));
                }
            }
        }
        
        public ObservableCollection<LogEntry> FilteredLogEntries
        {
            get => _filteredLogEntries;
            set
            {
                _filteredLogEntries = value;
                OnPropertyChanged(nameof(FilteredLogEntries));
            }
        }
        
        public List<string> LogLevels { get; } = new List<string> { "All", "Debug", "Information", "Warning", "Error", "Critical" };
        
        public ICommand RefreshCommand { get; }
        public ICommand ExportCommand { get; }
        public ICommand ClearLogsCommand { get; }
        
        private void RefreshLogs()
        {
            try
            {
                _allLogEntries.Clear();
                
                string logsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WinSecMonitor",
                    "Logs");
                    
                if (!Directory.Exists(logsPath))
                {
                    StatusText = "Log directory does not exist yet";
                    return;
                }
                
                // Get all log files
                var logFiles = Directory.GetFiles(logsPath, "*.log");
                
                foreach (var logFile in logFiles)
                {
                    try
                    {
                        var lines = File.ReadAllLines(logFile);
                        ParseLogLines(lines);
                    }
                    catch (Exception ex)
                    {
                        StatusText = $"Error reading log file {Path.GetFileName(logFile)}: {ex.Message}";
                    }
                }
                
                // Sort by timestamp descending (newest first)
                var sorted = _allLogEntries.OrderByDescending(e => e.Timestamp).ToList();
                _allLogEntries = new ObservableCollection<LogEntry>(sorted);
                
                ApplyFilters();
                StatusText = $"Loaded {_allLogEntries.Count} log entries";
            }
            catch (Exception ex)
            {
                StatusText = $"Error refreshing logs: {ex.Message}";
                MessageBox.Show($"Error refreshing logs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ParseLogLines(string[] lines)
        {
            // Regular expression to parse log lines
            // Format: [yyyy-MM-dd HH:mm:ss] [Level] Message
            var regex = new Regex(@"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (.+)");
            
            foreach (var line in lines)
            {
                var match = regex.Match(line);
                if (match.Success)
                {
                    var timestamp = DateTime.Parse(match.Groups[1].Value);
                    var level = match.Groups[2].Value;
                    var message = match.Groups[3].Value;
                    
                    _allLogEntries.Add(new LogEntry
                    {
                        Timestamp = timestamp,
                        Level = level,
                        Message = message
                    });
                }
            }
        }
        
        private void ApplyFilters()
        {
            try
            {
                IEnumerable<LogEntry> filtered = _allLogEntries;
                
                // Apply text filter
                if (!string.IsNullOrWhiteSpace(FilterText))
                {
                    filtered = filtered.Where(e => e.Message.Contains(FilterText, StringComparison.OrdinalIgnoreCase));
                }
                
                // Apply level filter
                if (SelectedLogLevel != "All")
                {
                    filtered = filtered.Where(e => e.Level == SelectedLogLevel);
                }
                
                // Apply date filter
                if (SelectedDate.HasValue)
                {
                    var date = SelectedDate.Value.Date;
                    filtered = filtered.Where(e => e.Timestamp.Date == date);
                }
                
                FilteredLogEntries = new ObservableCollection<LogEntry>(filtered);
                StatusText = $"Showing {FilteredLogEntries.Count} of {_allLogEntries.Count} log entries";
            }
            catch (Exception ex)
            {
                StatusText = $"Error applying filters: {ex.Message}";
            }
        }
        
        private void ExportLogs()
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    DefaultExt = ".csv",
                    FileName = $"WinSecMonitor_Logs_{DateTime.Now:yyyyMMdd_HHmmss}"
                };
                
                if (dialog.ShowDialog() == true)
                {
                    using (var writer = new StreamWriter(dialog.FileName))
                    {
                        // Write header
                        writer.WriteLine("Timestamp,Level,Message");
                        
                        // Write entries
                        foreach (var entry in FilteredLogEntries)
                        {
                            // Escape quotes in message
                            var message = entry.Message.Replace("\"", "\"\"");
                            writer.WriteLine($"{entry.Timestamp:yyyy-MM-dd HH:mm:ss},\"{entry.Level}\",\"{message}\"");
                        }
                    }
                    
                    StatusText = $"Exported {FilteredLogEntries.Count} log entries to {dialog.FileName}";
                }
            }
            catch (Exception ex)
            {
                StatusText = $"Error exporting logs: {ex.Message}";
                MessageBox.Show($"Error exporting logs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void ClearLogs()
        {
            try
            {
                var result = MessageBox.Show(
                    "Are you sure you want to clear all log files? This action cannot be undone.",
                    "Confirm Clear Logs",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                    
                if (result == MessageBoxResult.Yes)
                {
                    string logsPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "WinSecMonitor",
                        "Logs");
                        
                    if (Directory.Exists(logsPath))
                    {
                        var logFiles = Directory.GetFiles(logsPath, "*.log");
                        foreach (var file in logFiles)
                        {
                            File.Delete(file);
                        }
                        
                        _allLogEntries.Clear();
                        FilteredLogEntries.Clear();
                        StatusText = "All log files cleared";
                        
                        // Create a new empty log file
                        Logger.Instance.LogInformation("Log files cleared by user");
                        RefreshLogs();
                    }
                }
            }
            catch (Exception ex)
            {
                StatusText = $"Error clearing logs: {ex.Message}";
                MessageBox.Show($"Error clearing logs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
    
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Level { get; set; }
        public string Message { get; set; }
    }
}