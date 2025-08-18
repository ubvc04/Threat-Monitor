using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Views;

namespace WinSecMonitor;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }
    
    private void LogViewer_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var logViewer = new LogViewerWindow();
            logViewer.Owner = this;
            logViewer.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error opening Log Viewer: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Logger.Instance.LogError($"Error opening Log Viewer: {ex.Message}");
        }
    }
    
    private void DebugSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var debugSettings = new DebugSettingsWindow();
            debugSettings.Owner = this;
            debugSettings.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error opening Debug Settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Logger.Instance.LogError($"Error opening Debug Settings: {ex.Message}");
        }
    }
    
    private void ExportSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Settings files (*.json)|*.json|All files (*.*)|*.*",
                DefaultExt = ".json",
                FileName = $"WinSecMonitor_Settings_{DateTime.Now:yyyyMMdd}"
            };
            
            if (dialog.ShowDialog() == true)
            {
                // TODO: Implement settings export
                MessageBox.Show("Settings export not yet implemented", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                Logger.Instance.LogInformation($"Settings export requested to {dialog.FileName}");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error exporting settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Logger.Instance.LogError($"Error exporting settings: {ex.Message}");
        }
    }
    
    private void ImportSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Settings files (*.json)|*.json|All files (*.*)|*.*",
                DefaultExt = ".json"
            };
            
            if (dialog.ShowDialog() == true)
            {
                // TODO: Implement settings import
                MessageBox.Show("Settings import not yet implemented", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                Logger.Instance.LogInformation($"Settings import requested from {dialog.FileName}");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error importing settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Logger.Instance.LogError($"Error importing settings: {ex.Message}");
        }
    }
    
    private void About_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            MessageBox.Show(
                "WinSecMonitor - Windows Security Monitoring Tool\n\n" +
                "Version: 1.0.0\n" +
                "© 2023 WinSecMonitor Team\n\n" +
                "A comprehensive security monitoring solution for Windows systems.",
                "About WinSecMonitor",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Logger.Instance.LogError($"Error showing About dialog: {ex.Message}");
        }
    }
    
    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Close();
        }
        catch (Exception ex)
        {
            Logger.Instance.LogError($"Error during application exit: {ex.Message}");
        }
    }
}