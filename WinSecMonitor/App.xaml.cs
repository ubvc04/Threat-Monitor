using System;
using System.Configuration;
using System.Data;
using System.Windows;
using WinSecMonitor.Utils.ErrorHandling;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.Configuration;

namespace WinSecMonitor;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Initialize global exception handling
        ExceptionHandler.Initialize(this);
        
        // Log application startup
        Logger.Instance.LogInformation("Application starting up");
        
        // Ensure configuration is loaded
        var config = ConfigManager.Instance;
        
        base.OnStartup(e);
    }
    
    protected override void OnExit(ExitEventArgs e)
    {
        // Log application exit
        Logger.Instance.LogInformation("Application shutting down");
        
        // Save any pending configuration changes
        ConfigManager.Instance.SaveConfiguration();
        
        base.OnExit(e);
    }
}

