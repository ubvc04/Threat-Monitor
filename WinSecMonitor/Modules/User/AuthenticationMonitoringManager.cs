using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Windows.Threading;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Modules.User
{
    public class AuthenticationMonitoringManager
    {
        private readonly Logger _logger;
        private readonly Dispatcher _dispatcher;
        private readonly Timer _refreshTimer;
        private readonly TimeSpan _refreshInterval = TimeSpan.FromMinutes(5);

        // Monitoring components
        public AuthenticationMonitor AuthMonitor { get; private set; }
        public RDPSessionMonitor RDPMonitor { get; private set; }
        public PrivilegeMonitor PrivilegeMonitor { get; private set; }
        public AlertGenerator AlertGenerator { get; private set; }

        // Events for UI updates
        public event EventHandler DataRefreshed;
        public event EventHandler<SecurityAlert> NewAlertGenerated;

        // Singleton instance
        private static AuthenticationMonitoringManager _instance;
        private static readonly object _lock = new object();

        public static AuthenticationMonitoringManager Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new AuthenticationMonitoringManager();
                        }
                    }
                }
                return _instance;
            }
        }

        // Properties for data binding
        public ObservableCollection<AuthenticationEvent> AuthenticationEvents => AuthMonitor?.AuthenticationEvents;
        public ObservableCollection<RDPSession> RDPSessions => RDPMonitor?.RDPSessions;
        public ObservableCollection<PrivilegeEvent> PrivilegeEvents => PrivilegeMonitor?.PrivilegeEvents;
        public ObservableCollection<SecurityAlert> ActiveAlerts => AlertGenerator?.ActiveAlerts;
        public ObservableCollection<SecurityAlert> AlertHistory => AlertGenerator?.AlertHistory;

        private AuthenticationMonitoringManager(Dispatcher dispatcher = null)
        {
            _logger = Logger.Instance;
            _dispatcher = dispatcher;

            try
            {
                _logger.LogInformation("Initializing Authentication Monitoring Manager");

                // Initialize monitoring components
                InitializeMonitors();

                // Set up refresh timer
                _refreshTimer = new Timer(RefreshTimerCallback, null, TimeSpan.Zero, _refreshInterval);

                _logger.LogInformation("Authentication Monitoring Manager initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing Authentication Monitoring Manager");
                throw;
            }
        }

        private void InitializeMonitors()
        {
            try
            {
                // Create monitoring components
                AuthMonitor = new AuthenticationMonitor();
                RDPMonitor = new RDPSessionMonitor();
                PrivilegeMonitor = new PrivilegeMonitor();

                // Initialize alert generator with monitors
                AlertGenerator = new AlertGenerator(AuthMonitor, RDPMonitor, PrivilegeMonitor, _dispatcher);

                // Subscribe to alert events
                AlertGenerator.NewAlertGenerated += (sender, alert) => NewAlertGenerated?.Invoke(this, alert);

                // Start monitoring
                AuthMonitor.StartMonitoring();
                RDPMonitor.StartMonitoring();
                PrivilegeMonitor.StartMonitoring();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error initializing monitoring components");
                throw;
            }
        }

        private void RefreshTimerCallback(object state)
        {
            try
            {
                RefreshAllData();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error in refresh timer callback");
            }
        }

        public void RefreshAllData()
        {
            try
            {
                _logger.LogDebug("Refreshing all authentication monitoring data");

                // Refresh all data sources
                AuthMonitor?.RefreshEvents();
                RDPMonitor?.RefreshSessions();
                PrivilegeMonitor?.RefreshEvents();

                // Notify UI
                DataRefreshed?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error refreshing authentication monitoring data");
            }
        }

        public void AcknowledgeAlert(SecurityAlert alert, string acknowledgedBy)
        {
            try
            {
                if (alert != null && AlertGenerator != null)
                {
                    AlertGenerator.AcknowledgeAlert(alert, acknowledgedBy);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging alert");
            }
        }

        public void AcknowledgeAllAlerts(string acknowledgedBy)
        {
            try
            {
                if (AlertGenerator != null)
                {
                    AlertGenerator.AcknowledgeAllAlerts(acknowledgedBy);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error acknowledging all alerts");
            }
        }

        public void ClearAlertHistory()
        {
            try
            {
                if (AlertGenerator != null)
                {
                    AlertGenerator.ClearAlertHistory();
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error clearing alert history");
            }
        }

        public void Shutdown()
        {
            try
            {
                _logger.LogInformation("Shutting down Authentication Monitoring Manager");

                // Stop the refresh timer
                _refreshTimer?.Dispose();

                // Stop monitoring components
                AuthMonitor?.StopMonitoring();
                RDPMonitor?.StopMonitoring();
                PrivilegeMonitor?.StopMonitoring();
            }
            catch (Exception ex)
            {
                _logger.LogException(ex, "Error shutting down Authentication Monitoring Manager");
            }
        }
    }
}