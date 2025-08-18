using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WinSecMonitor.Utils.Logging;
using WinSecMonitor.Utils.ErrorHandling;

namespace WinSecMonitor.Modules.Compliance
{
    /// <summary>
    /// Generates detailed compliance reports based on Windows updates, security policies, and software versions
    /// </summary>
    public class ComplianceReportGenerator
    {
        private readonly Logger _logger = Logger.GetInstance();
        private readonly SafeExceptionHandler _exceptionHandler = new SafeExceptionHandler();

        public event EventHandler<ReportGenerationProgressEventArgs> ReportGenerationProgress;
        public event EventHandler<ReportGenerationCompletedEventArgs> ReportGenerationCompleted;

        private readonly WindowsUpdateChecker _updateChecker;
        private readonly SecurityPolicyMonitor _policyMonitor;
        private readonly SoftwareVersionChecker _softwareChecker;

        public ComplianceReportGenerator(WindowsUpdateChecker updateChecker, SecurityPolicyMonitor policyMonitor, SoftwareVersionChecker softwareChecker)
        {
            _updateChecker = updateChecker ?? throw new ArgumentNullException(nameof(updateChecker));
            _policyMonitor = policyMonitor ?? throw new ArgumentNullException(nameof(policyMonitor));
            _softwareChecker = softwareChecker ?? throw new ArgumentNullException(nameof(softwareChecker));
        }

        /// <summary>
        /// Generates a comprehensive compliance report
        /// </summary>
        public async Task<ComplianceReport> GenerateComprehensiveReportAsync()
        {
            try
            {
                OnReportGenerationProgress("Initializing report generation...", 0);

                ComplianceReport report = new ComplianceReport
                {
                    GenerationTime = DateTime.Now,
                    MachineName = Environment.MachineName,
                    OperatingSystem = Environment.OSVersion.ToString(),
                    UserName = Environment.UserName
                };

                // Check Windows updates
                OnReportGenerationProgress("Checking Windows updates...", 10);
                if (_updateChecker.LastCheckTime == DateTime.MinValue)
                {
                    await _updateChecker.CheckForUpdatesAsync();
                }

                // Add Windows update information to report
                report.MissingUpdatesCount = _updateChecker.MissingUpdatesCount;
                report.CriticalUpdatesCount = _updateChecker.CriticalUpdatesCount;
                report.SecurityUpdatesCount = _updateChecker.SecurityUpdatesCount;
                report.MissingUpdates = _updateChecker.AvailableUpdates.ToList();

                // Check security policies
                OnReportGenerationProgress("Checking security policies...", 40);
                if (_policyMonitor.LastCheckTime == DateTime.MinValue)
                {
                    await _policyMonitor.CheckAllPoliciesAsync();
                }

                // Add security policy information to report
                report.FirewallPolicies = _policyMonitor.FirewallPolicies.ToList();
                report.PasswordPolicies = _policyMonitor.PasswordPolicies.ToList();
                report.AuditPolicies = _policyMonitor.AuditPolicies.ToList();
                report.GroupPolicies = _policyMonitor.GroupPolicies.ToList();
                report.NonCompliantPoliciesCount = _policyMonitor.NonCompliantPoliciesCount;

                // Check software versions
                OnReportGenerationProgress("Checking software versions...", 70);
                if (_softwareChecker.LastCheckTime == DateTime.MinValue)
                {
                    await _softwareChecker.CheckSoftwareAsync();
                }

                // Add software version information to report
                report.OutdatedSoftwareCount = _softwareChecker.OutdatedSoftwareCount;
                report.VulnerableSoftwareCount = _softwareChecker.VulnerableSoftwareCount;
                report.InstalledSoftware = _softwareChecker.InstalledSoftware.ToList();

                // Calculate overall compliance score
                report.CalculateComplianceScore();

                OnReportGenerationProgress("Report generation completed", 100);
                OnReportGenerationCompleted(true, null, report);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating compliance report: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error generating compliance report");
                OnReportGenerationCompleted(false, ex.Message, null);
                throw;
            }
        }

        /// <summary>
        /// Generates a Windows update report
        /// </summary>
        public async Task<WindowsUpdateReport> GenerateWindowsUpdateReportAsync()
        {
            try
            {
                OnReportGenerationProgress("Initializing Windows update report...", 0);

                WindowsUpdateReport report = new WindowsUpdateReport
                {
                    GenerationTime = DateTime.Now,
                    MachineName = Environment.MachineName,
                    OperatingSystem = Environment.OSVersion.ToString(),
                    UserName = Environment.UserName
                };

                // Check Windows updates
                OnReportGenerationProgress("Checking Windows updates...", 20);
                if (_updateChecker.LastCheckTime == DateTime.MinValue)
                {
                    await _updateChecker.CheckForUpdatesAsync();
                }

                // Add Windows update information to report
                report.MissingUpdatesCount = _updateChecker.MissingUpdatesCount;
                report.CriticalUpdatesCount = _updateChecker.CriticalUpdatesCount;
                report.SecurityUpdatesCount = _updateChecker.SecurityUpdatesCount;
                report.MissingUpdates = _updateChecker.AvailableUpdates.ToList();
                report.InstalledUpdates = _updateChecker.InstalledUpdates.ToList();

                // Calculate update compliance score
                report.CalculateUpdateComplianceScore();

                OnReportGenerationProgress("Windows update report completed", 100);
                OnReportGenerationCompleted(true, null, report);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating Windows update report: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error generating Windows update report");
                OnReportGenerationCompleted(false, ex.Message, null);
                throw;
            }
        }

        /// <summary>
        /// Generates a security policy report
        /// </summary>
        public async Task<SecurityPolicyReport> GenerateSecurityPolicyReportAsync()
        {
            try
            {
                OnReportGenerationProgress("Initializing security policy report...", 0);

                SecurityPolicyReport report = new SecurityPolicyReport
                {
                    GenerationTime = DateTime.Now,
                    MachineName = Environment.MachineName,
                    OperatingSystem = Environment.OSVersion.ToString(),
                    UserName = Environment.UserName
                };

                // Check security policies
                OnReportGenerationProgress("Checking security policies...", 20);
                if (_policyMonitor.LastCheckTime == DateTime.MinValue)
                {
                    await _policyMonitor.CheckAllPoliciesAsync();
                }

                // Add security policy information to report
                report.FirewallPolicies = _policyMonitor.FirewallPolicies.ToList();
                report.PasswordPolicies = _policyMonitor.PasswordPolicies.ToList();
                report.AuditPolicies = _policyMonitor.AuditPolicies.ToList();
                report.GroupPolicies = _policyMonitor.GroupPolicies.ToList();
                report.NonCompliantPoliciesCount = _policyMonitor.NonCompliantPoliciesCount;

                // Calculate policy compliance score
                report.CalculatePolicyComplianceScore();

                OnReportGenerationProgress("Security policy report completed", 100);
                OnReportGenerationCompleted(true, null, report);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating security policy report: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error generating security policy report");
                OnReportGenerationCompleted(false, ex.Message, null);
                throw;
            }
        }

        /// <summary>
        /// Generates a software version report
        /// </summary>
        public async Task<SoftwareVersionReport> GenerateSoftwareVersionReportAsync()
        {
            try
            {
                OnReportGenerationProgress("Initializing software version report...", 0);

                SoftwareVersionReport report = new SoftwareVersionReport
                {
                    GenerationTime = DateTime.Now,
                    MachineName = Environment.MachineName,
                    OperatingSystem = Environment.OSVersion.ToString(),
                    UserName = Environment.UserName
                };

                // Check software versions
                OnReportGenerationProgress("Checking software versions...", 20);
                if (_softwareChecker.LastCheckTime == DateTime.MinValue)
                {
                    await _softwareChecker.CheckSoftwareAsync();
                }

                // Add software version information to report
                report.OutdatedSoftwareCount = _softwareChecker.OutdatedSoftwareCount;
                report.VulnerableSoftwareCount = _softwareChecker.VulnerableSoftwareCount;
                report.InstalledSoftware = _softwareChecker.InstalledSoftware.ToList();

                // Calculate software compliance score
                report.CalculateSoftwareComplianceScore();

                OnReportGenerationProgress("Software version report completed", 100);
                OnReportGenerationCompleted(true, null, report);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error generating software version report: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error generating software version report");
                OnReportGenerationCompleted(false, ex.Message, null);
                throw;
            }
        }

        /// <summary>
        /// Exports a report to CSV format
        /// </summary>
        public async Task<string> ExportReportToCsvAsync(BaseReport report, string filePath)
        {
            try
            {
                OnReportGenerationProgress("Exporting report to CSV...", 0);

                if (report == null)
                    throw new ArgumentNullException(nameof(report));

                StringBuilder csv = new StringBuilder();

                // Add report header
                csv.AppendLine($"Report Type,{report.GetType().Name}");
                csv.AppendLine($"Generation Time,{report.GenerationTime}");
                csv.AppendLine($"Machine Name,{report.MachineName}");
                csv.AppendLine($"Operating System,{report.OperatingSystem}");
                csv.AppendLine($"User Name,{report.UserName}");
                csv.AppendLine();

                // Add report-specific data
                if (report is ComplianceReport comprehensiveReport)
                {
                    // Add compliance score
                    csv.AppendLine($"Overall Compliance Score,{comprehensiveReport.ComplianceScore}%");
                    csv.AppendLine();

                    // Add Windows update summary
                    csv.AppendLine("Windows Update Summary");
                    csv.AppendLine($"Missing Updates,{comprehensiveReport.MissingUpdatesCount}");
                    csv.AppendLine($"Critical Updates,{comprehensiveReport.CriticalUpdatesCount}");
                    csv.AppendLine($"Security Updates,{comprehensiveReport.SecurityUpdatesCount}");
                    csv.AppendLine();

                    // Add security policy summary
                    csv.AppendLine("Security Policy Summary");
                    csv.AppendLine($"Non-Compliant Policies,{comprehensiveReport.NonCompliantPoliciesCount}");
                    csv.AppendLine();

                    // Add software version summary
                    csv.AppendLine("Software Version Summary");
                    csv.AppendLine($"Outdated Software,{comprehensiveReport.OutdatedSoftwareCount}");
                    csv.AppendLine($"Vulnerable Software,{comprehensiveReport.VulnerableSoftwareCount}");
                    csv.AppendLine();

                    // Add missing updates
                    csv.AppendLine("Missing Updates");
                    csv.AppendLine("KB Article,Title,Severity,Category,Release Date");
                    foreach (var update in comprehensiveReport.MissingUpdates)
                    {
                        csv.AppendLine($"{update.KBArticleID},{EscapeCsvField(update.Title)},{update.Severity},{update.Category},{update.ReleaseDate.ToShortDateString()}");
                    }
                    csv.AppendLine();

                    // Add non-compliant policies
                    csv.AppendLine("Non-Compliant Policies");
                    csv.AppendLine("Name,Category,Status,Recommendation");
                    var nonCompliantPolicies = comprehensiveReport.FirewallPolicies.Where(p => p.Status == PolicyStatus.NonCompliant)
                        .Concat(comprehensiveReport.PasswordPolicies.Where(p => p.Status == PolicyStatus.NonCompliant))
                        .Concat(comprehensiveReport.AuditPolicies.Where(p => p.Status == PolicyStatus.NonCompliant))
                        .Concat(comprehensiveReport.GroupPolicies.Where(p => p.Status == PolicyStatus.NonCompliant));

                    foreach (var policy in nonCompliantPolicies)
                    {
                        csv.AppendLine($"{EscapeCsvField(policy.Name)},{policy.Category},{policy.Status},{EscapeCsvField(policy.Recommendation)}");
                    }
                    csv.AppendLine();

                    // Add outdated and vulnerable software
                    csv.AppendLine("Outdated and Vulnerable Software");
                    csv.AppendLine("Name,Version,Latest Version,Status,Vendor,Install Date");
                    var problematicSoftware = comprehensiveReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Outdated || s.Status == SoftwareStatus.Vulnerable);

                    foreach (var software in problematicSoftware)
                    {
                        csv.AppendLine($"{EscapeCsvField(software.Name)},{software.Version},{software.LatestVersion},{software.Status},{EscapeCsvField(software.Vendor)},{software.InstallDateString}");
                    }
                }
                else if (report is WindowsUpdateReport updateReport)
                {
                    // Add update compliance score
                    csv.AppendLine($"Update Compliance Score,{updateReport.UpdateComplianceScore}%");
                    csv.AppendLine();

                    // Add Windows update summary
                    csv.AppendLine("Windows Update Summary");
                    csv.AppendLine($"Missing Updates,{updateReport.MissingUpdatesCount}");
                    csv.AppendLine($"Critical Updates,{updateReport.CriticalUpdatesCount}");
                    csv.AppendLine($"Security Updates,{updateReport.SecurityUpdatesCount}");
                    csv.AppendLine();

                    // Add missing updates
                    csv.AppendLine("Missing Updates");
                    csv.AppendLine("KB Article,Title,Severity,Category,Release Date");
                    foreach (var update in updateReport.MissingUpdates)
                    {
                        csv.AppendLine($"{update.KBArticleID},{EscapeCsvField(update.Title)},{update.Severity},{update.Category},{update.ReleaseDate.ToShortDateString()}");
                    }
                    csv.AppendLine();

                    // Add installed updates
                    csv.AppendLine("Recently Installed Updates");
                    csv.AppendLine("KB Article,Title,Install Date");
                    foreach (var update in updateReport.InstalledUpdates.OrderByDescending(u => u.InstallDate).Take(20))
                    {
                        csv.AppendLine($"{update.KBArticleID},{EscapeCsvField(update.Title)},{update.InstallDate.ToShortDateString()}");
                    }
                }
                else if (report is SecurityPolicyReport policyReport)
                {
                    // Add policy compliance score
                    csv.AppendLine($"Policy Compliance Score,{policyReport.PolicyComplianceScore}%");
                    csv.AppendLine();

                    // Add security policy summary
                    csv.AppendLine("Security Policy Summary");
                    csv.AppendLine($"Non-Compliant Policies,{policyReport.NonCompliantPoliciesCount}");
                    csv.AppendLine();

                    // Add firewall policies
                    csv.AppendLine("Firewall Policies");
                    csv.AppendLine("Name,Status,Current Value,Expected Value,Recommendation");
                    foreach (var policy in policyReport.FirewallPolicies)
                    {
                        csv.AppendLine($"{EscapeCsvField(policy.Name)},{policy.Status},{EscapeCsvField(policy.CurrentValue)},{EscapeCsvField(policy.ExpectedValue)},{EscapeCsvField(policy.Recommendation)}");
                    }
                    csv.AppendLine();

                    // Add password policies
                    csv.AppendLine("Password Policies");
                    csv.AppendLine("Name,Status,Current Value,Expected Value,Recommendation");
                    foreach (var policy in policyReport.PasswordPolicies)
                    {
                        csv.AppendLine($"{EscapeCsvField(policy.Name)},{policy.Status},{EscapeCsvField(policy.CurrentValue)},{EscapeCsvField(policy.ExpectedValue)},{EscapeCsvField(policy.Recommendation)}");
                    }
                    csv.AppendLine();

                    // Add audit policies
                    csv.AppendLine("Audit Policies");
                    csv.AppendLine("Name,Status,Current Value,Expected Value,Recommendation");
                    foreach (var policy in policyReport.AuditPolicies)
                    {
                        csv.AppendLine($"{EscapeCsvField(policy.Name)},{policy.Status},{EscapeCsvField(policy.CurrentValue)},{EscapeCsvField(policy.ExpectedValue)},{EscapeCsvField(policy.Recommendation)}");
                    }
                    csv.AppendLine();

                    // Add group policies
                    csv.AppendLine("Group Policies");
                    csv.AppendLine("Name,Status,Current Value,Expected Value,Recommendation");
                    foreach (var policy in policyReport.GroupPolicies)
                    {
                        csv.AppendLine($"{EscapeCsvField(policy.Name)},{policy.Status},{EscapeCsvField(policy.CurrentValue)},{EscapeCsvField(policy.ExpectedValue)},{EscapeCsvField(policy.Recommendation)}");
                    }
                }
                else if (report is SoftwareVersionReport softwareReport)
                {
                    // Add software compliance score
                    csv.AppendLine($"Software Compliance Score,{softwareReport.SoftwareComplianceScore}%");
                    csv.AppendLine();

                    // Add software version summary
                    csv.AppendLine("Software Version Summary");
                    csv.AppendLine($"Outdated Software,{softwareReport.OutdatedSoftwareCount}");
                    csv.AppendLine($"Vulnerable Software,{softwareReport.VulnerableSoftwareCount}");
                    csv.AppendLine();

                    // Add outdated software
                    csv.AppendLine("Outdated Software");
                    csv.AppendLine("Name,Current Version,Latest Version,Vendor,Install Date");
                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Outdated))
                    {
                        csv.AppendLine($"{EscapeCsvField(software.Name)},{software.Version},{software.LatestVersion},{EscapeCsvField(software.Vendor)},{software.InstallDateString}");
                    }
                    csv.AppendLine();

                    // Add vulnerable software
                    csv.AppendLine("Vulnerable Software");
                    csv.AppendLine("Name,Version,Vulnerability Info,Vendor,Install Date");
                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Vulnerable))
                    {
                        csv.AppendLine($"{EscapeCsvField(software.Name)},{software.Version},{EscapeCsvField(software.VulnerabilityInfo)},{EscapeCsvField(software.Vendor)},{software.InstallDateString}");
                    }
                    csv.AppendLine();

                    // Add up-to-date software
                    csv.AppendLine("Up-to-Date Software");
                    csv.AppendLine("Name,Version,Vendor,Install Date");
                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.UpToDate))
                    {
                        csv.AppendLine($"{EscapeCsvField(software.Name)},{software.Version},{EscapeCsvField(software.Vendor)},{software.InstallDateString}");
                    }
                }

                // Write to file
                OnReportGenerationProgress("Writing CSV file...", 80);
                await File.WriteAllTextAsync(filePath, csv.ToString());

                OnReportGenerationProgress("CSV export completed", 100);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error exporting report to CSV: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error exporting report to CSV");
                throw;
            }
        }

        /// <summary>
        /// Exports a report to HTML format
        /// </summary>
        public async Task<string> ExportReportToHtmlAsync(BaseReport report, string filePath)
        {
            try
            {
                OnReportGenerationProgress("Exporting report to HTML...", 0);

                if (report == null)
                    throw new ArgumentNullException(nameof(report));

                StringBuilder html = new StringBuilder();

                // Add HTML header
                html.AppendLine("<!DOCTYPE html>");
                html.AppendLine("<html lang=\"en\">");
                html.AppendLine("<head>");
                html.AppendLine("    <meta charset=\"UTF-8\">");
                html.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
                html.AppendLine($"    <title>{report.GetType().Name} - {report.GenerationTime}</title>");
                html.AppendLine("    <style>");
                html.AppendLine("        body { font-family: Arial, sans-serif; margin: 20px; }");
                html.AppendLine("        h1, h2, h3 { color: #333; }");
                html.AppendLine("        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }");
                html.AppendLine("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
                html.AppendLine("        th { background-color: #f2f2f2; }");
                html.AppendLine("        tr:nth-child(even) { background-color: #f9f9f9; }");
                html.AppendLine("        .compliant { color: green; }");
                html.AppendLine("        .non-compliant { color: red; }");
                html.AppendLine("        .unknown { color: orange; }");
                html.AppendLine("        .up-to-date { color: green; }");
                html.AppendLine("        .outdated { color: orange; }");
                html.AppendLine("        .vulnerable { color: red; }");
                html.AppendLine("        .critical { color: darkred; font-weight: bold; }");
                html.AppendLine("        .important { color: red; }");
                html.AppendLine("        .moderate { color: orange; }");
                html.AppendLine("        .low { color: blue; }");
                html.AppendLine("        .summary-box { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; background-color: #f9f9f9; }");
                html.AppendLine("        .score { font-size: 24px; font-weight: bold; }");
                html.AppendLine("        .good-score { color: green; }");
                html.AppendLine("        .medium-score { color: orange; }");
                html.AppendLine("        .bad-score { color: red; }");
                html.AppendLine("    </style>");
                html.AppendLine("</head>");
                html.AppendLine("<body>");

                // Add report header
                html.AppendLine($"    <h1>{report.GetType().Name}</h1>");
                html.AppendLine("    <div class=\"summary-box\">");
                html.AppendLine($"        <p><strong>Generation Time:</strong> {report.GenerationTime}</p>");
                html.AppendLine($"        <p><strong>Machine Name:</strong> {report.MachineName}</p>");
                html.AppendLine($"        <p><strong>Operating System:</strong> {report.OperatingSystem}</p>");
                html.AppendLine($"        <p><strong>User Name:</strong> {report.UserName}</p>");
                html.AppendLine("    </div>");

                // Add report-specific data
                if (report is ComplianceReport comprehensiveReport)
                {
                    // Add compliance score
                    string scoreClass = comprehensiveReport.ComplianceScore >= 80 ? "good-score" : 
                                       comprehensiveReport.ComplianceScore >= 60 ? "medium-score" : "bad-score";
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <h2>Overall Compliance Score: <span class=\"score {scoreClass}\">{comprehensiveReport.ComplianceScore}%</span></h2>");
                    html.AppendLine("    </div>");

                    // Add Windows update summary
                    html.AppendLine("    <h2>Windows Update Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Missing Updates:</strong> {comprehensiveReport.MissingUpdatesCount}</p>");
                    html.AppendLine($"        <p><strong>Critical Updates:</strong> {comprehensiveReport.CriticalUpdatesCount}</p>");
                    html.AppendLine($"        <p><strong>Security Updates:</strong> {comprehensiveReport.SecurityUpdatesCount}</p>");
                    html.AppendLine("    </div>");

                    // Add security policy summary
                    html.AppendLine("    <h2>Security Policy Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Non-Compliant Policies:</strong> {comprehensiveReport.NonCompliantPoliciesCount}</p>");
                    html.AppendLine("    </div>");

                    // Add software version summary
                    html.AppendLine("    <h2>Software Version Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Outdated Software:</strong> {comprehensiveReport.OutdatedSoftwareCount}</p>");
                    html.AppendLine($"        <p><strong>Vulnerable Software:</strong> {comprehensiveReport.VulnerableSoftwareCount}</p>");
                    html.AppendLine("    </div>");

                    // Add missing updates
                    html.AppendLine("    <h2>Missing Updates</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>KB Article</th>");
                    html.AppendLine("            <th>Title</th>");
                    html.AppendLine("            <th>Severity</th>");
                    html.AppendLine("            <th>Category</th>");
                    html.AppendLine("            <th>Release Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var update in comprehensiveReport.MissingUpdates)
                    {
                        string severityClass = update.Severity == UpdateSeverity.Critical ? "critical" :
                                             update.Severity == UpdateSeverity.Important ? "important" :
                                             update.Severity == UpdateSeverity.Moderate ? "moderate" : "low";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{update.KBArticleID}</td>");
                        html.AppendLine($"            <td>{update.Title}</td>");
                        html.AppendLine($"            <td class=\"{severityClass}\">{update.Severity}</td>");
                        html.AppendLine($"            <td>{update.Category}</td>");
                        html.AppendLine($"            <td>{update.ReleaseDate.ToShortDateString()}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add non-compliant policies
                    html.AppendLine("    <h2>Non-Compliant Policies</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Category</th>");
                    html.AppendLine("            <th>Current Value</th>");
                    html.AppendLine("            <th>Expected Value</th>");
                    html.AppendLine("            <th>Recommendation</th>");
                    html.AppendLine("        </tr>");

                    var nonCompliantPolicies = comprehensiveReport.FirewallPolicies.Where(p => p.Status == PolicyStatus.NonCompliant)
                        .Concat(comprehensiveReport.PasswordPolicies.Where(p => p.Status == PolicyStatus.NonCompliant))
                        .Concat(comprehensiveReport.AuditPolicies.Where(p => p.Status == PolicyStatus.NonCompliant))
                        .Concat(comprehensiveReport.GroupPolicies.Where(p => p.Status == PolicyStatus.NonCompliant));

                    foreach (var policy in nonCompliantPolicies)
                    {
                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{policy.Name}</td>");
                        html.AppendLine($"            <td>{policy.Category}</td>");
                        html.AppendLine($"            <td>{policy.CurrentValue}</td>");
                        html.AppendLine($"            <td>{policy.ExpectedValue}</td>");
                        html.AppendLine($"            <td>{policy.Recommendation}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add outdated and vulnerable software
                    html.AppendLine("    <h2>Outdated and Vulnerable Software</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Current Version</th>");
                    html.AppendLine("            <th>Latest Version</th>");
                    html.AppendLine("            <th>Status</th>");
                    html.AppendLine("            <th>Vendor</th>");
                    html.AppendLine("            <th>Install Date</th>");
                    html.AppendLine("        </tr>");

                    var problematicSoftware = comprehensiveReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Outdated || s.Status == SoftwareStatus.Vulnerable);

                    foreach (var software in problematicSoftware)
                    {
                        string statusClass = software.Status == SoftwareStatus.Vulnerable ? "vulnerable" : "outdated";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{software.Name}</td>");
                        html.AppendLine($"            <td>{software.Version}</td>");
                        html.AppendLine($"            <td>{software.LatestVersion}</td>");
                        html.AppendLine($"            <td class=\"{statusClass}\">{software.Status}</td>");
                        html.AppendLine($"            <td>{software.Vendor}</td>");
                        html.AppendLine($"            <td>{software.InstallDateString}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");
                }
                else if (report is WindowsUpdateReport updateReport)
                {
                    // Add update compliance score
                    string scoreClass = updateReport.UpdateComplianceScore >= 80 ? "good-score" : 
                                       updateReport.UpdateComplianceScore >= 60 ? "medium-score" : "bad-score";
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <h2>Update Compliance Score: <span class=\"score {scoreClass}\">{updateReport.UpdateComplianceScore}%</span></h2>");
                    html.AppendLine("    </div>");

                    // Add Windows update summary
                    html.AppendLine("    <h2>Windows Update Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Missing Updates:</strong> {updateReport.MissingUpdatesCount}</p>");
                    html.AppendLine($"        <p><strong>Critical Updates:</strong> {updateReport.CriticalUpdatesCount}</p>");
                    html.AppendLine($"        <p><strong>Security Updates:</strong> {updateReport.SecurityUpdatesCount}</p>");
                    html.AppendLine("    </div>");

                    // Add missing updates
                    html.AppendLine("    <h2>Missing Updates</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>KB Article</th>");
                    html.AppendLine("            <th>Title</th>");
                    html.AppendLine("            <th>Severity</th>");
                    html.AppendLine("            <th>Category</th>");
                    html.AppendLine("            <th>Release Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var update in updateReport.MissingUpdates)
                    {
                        string severityClass = update.Severity == UpdateSeverity.Critical ? "critical" :
                                             update.Severity == UpdateSeverity.Important ? "important" :
                                             update.Severity == UpdateSeverity.Moderate ? "moderate" : "low";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{update.KBArticleID}</td>");
                        html.AppendLine($"            <td>{update.Title}</td>");
                        html.AppendLine($"            <td class=\"{severityClass}\">{update.Severity}</td>");
                        html.AppendLine($"            <td>{update.Category}</td>");
                        html.AppendLine($"            <td>{update.ReleaseDate.ToShortDateString()}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add installed updates
                    html.AppendLine("    <h2>Recently Installed Updates</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>KB Article</th>");
                    html.AppendLine("            <th>Title</th>");
                    html.AppendLine("            <th>Install Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var update in updateReport.InstalledUpdates.OrderByDescending(u => u.InstallDate).Take(20))
                    {
                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{update.KBArticleID}</td>");
                        html.AppendLine($"            <td>{update.Title}</td>");
                        html.AppendLine($"            <td>{update.InstallDate.ToShortDateString()}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");
                }
                else if (report is SecurityPolicyReport policyReport)
                {
                    // Add policy compliance score
                    string scoreClass = policyReport.PolicyComplianceScore >= 80 ? "good-score" : 
                                       policyReport.PolicyComplianceScore >= 60 ? "medium-score" : "bad-score";
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <h2>Policy Compliance Score: <span class=\"score {scoreClass}\">{policyReport.PolicyComplianceScore}%</span></h2>");
                    html.AppendLine("    </div>");

                    // Add security policy summary
                    html.AppendLine("    <h2>Security Policy Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Non-Compliant Policies:</strong> {policyReport.NonCompliantPoliciesCount}</p>");
                    html.AppendLine("    </div>");

                    // Add firewall policies
                    html.AppendLine("    <h2>Firewall Policies</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Status</th>");
                    html.AppendLine("            <th>Current Value</th>");
                    html.AppendLine("            <th>Expected Value</th>");
                    html.AppendLine("            <th>Recommendation</th>");
                    html.AppendLine("        </tr>");

                    foreach (var policy in policyReport.FirewallPolicies)
                    {
                        string statusClass = policy.Status == PolicyStatus.Compliant ? "compliant" : 
                                           policy.Status == PolicyStatus.NonCompliant ? "non-compliant" : "unknown";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{policy.Name}</td>");
                        html.AppendLine($"            <td class=\"{statusClass}\">{policy.Status}</td>");
                        html.AppendLine($"            <td>{policy.CurrentValue}</td>");
                        html.AppendLine($"            <td>{policy.ExpectedValue}</td>");
                        html.AppendLine($"            <td>{policy.Recommendation}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add password policies
                    html.AppendLine("    <h2>Password Policies</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Status</th>");
                    html.AppendLine("            <th>Current Value</th>");
                    html.AppendLine("            <th>Expected Value</th>");
                    html.AppendLine("            <th>Recommendation</th>");
                    html.AppendLine("        </tr>");

                    foreach (var policy in policyReport.PasswordPolicies)
                    {
                        string statusClass = policy.Status == PolicyStatus.Compliant ? "compliant" : 
                                           policy.Status == PolicyStatus.NonCompliant ? "non-compliant" : "unknown";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{policy.Name}</td>");
                        html.AppendLine($"            <td class=\"{statusClass}\">{policy.Status}</td>");
                        html.AppendLine($"            <td>{policy.CurrentValue}</td>");
                        html.AppendLine($"            <td>{policy.ExpectedValue}</td>");
                        html.AppendLine($"            <td>{policy.Recommendation}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add audit policies
                    html.AppendLine("    <h2>Audit Policies</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Status</th>");
                    html.AppendLine("            <th>Current Value</th>");
                    html.AppendLine("            <th>Expected Value</th>");
                    html.AppendLine("            <th>Recommendation</th>");
                    html.AppendLine("        </tr>");

                    foreach (var policy in policyReport.AuditPolicies)
                    {
                        string statusClass = policy.Status == PolicyStatus.Compliant ? "compliant" : 
                                           policy.Status == PolicyStatus.NonCompliant ? "non-compliant" : "unknown";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{policy.Name}</td>");
                        html.AppendLine($"            <td class=\"{statusClass}\">{policy.Status}</td>");
                        html.AppendLine($"            <td>{policy.CurrentValue}</td>");
                        html.AppendLine($"            <td>{policy.ExpectedValue}</td>");
                        html.AppendLine($"            <td>{policy.Recommendation}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add group policies
                    html.AppendLine("    <h2>Group Policies</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Status</th>");
                    html.AppendLine("            <th>Current Value</th>");
                    html.AppendLine("            <th>Expected Value</th>");
                    html.AppendLine("            <th>Recommendation</th>");
                    html.AppendLine("        </tr>");

                    foreach (var policy in policyReport.GroupPolicies)
                    {
                        string statusClass = policy.Status == PolicyStatus.Compliant ? "compliant" : 
                                           policy.Status == PolicyStatus.NonCompliant ? "non-compliant" : "unknown";

                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{policy.Name}</td>");
                        html.AppendLine($"            <td class=\"{statusClass}\">{policy.Status}</td>");
                        html.AppendLine($"            <td>{policy.CurrentValue}</td>");
                        html.AppendLine($"            <td>{policy.ExpectedValue}</td>");
                        html.AppendLine($"            <td>{policy.Recommendation}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");
                }
                else if (report is SoftwareVersionReport softwareReport)
                {
                    // Add software compliance score
                    string scoreClass = softwareReport.SoftwareComplianceScore >= 80 ? "good-score" : 
                                       softwareReport.SoftwareComplianceScore >= 60 ? "medium-score" : "bad-score";
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <h2>Software Compliance Score: <span class=\"score {scoreClass}\">{softwareReport.SoftwareComplianceScore}%</span></h2>");
                    html.AppendLine("    </div>");

                    // Add software version summary
                    html.AppendLine("    <h2>Software Version Summary</h2>");
                    html.AppendLine("    <div class=\"summary-box\">");
                    html.AppendLine($"        <p><strong>Outdated Software:</strong> {softwareReport.OutdatedSoftwareCount}</p>");
                    html.AppendLine($"        <p><strong>Vulnerable Software:</strong> {softwareReport.VulnerableSoftwareCount}</p>");
                    html.AppendLine("    </div>");

                    // Add outdated software
                    html.AppendLine("    <h2>Outdated Software</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Current Version</th>");
                    html.AppendLine("            <th>Latest Version</th>");
                    html.AppendLine("            <th>Vendor</th>");
                    html.AppendLine("            <th>Install Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Outdated))
                    {
                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{software.Name}</td>");
                        html.AppendLine($"            <td class=\"outdated\">{software.Version}</td>");
                        html.AppendLine($"            <td>{software.LatestVersion}</td>");
                        html.AppendLine($"            <td>{software.Vendor}</td>");
                        html.AppendLine($"            <td>{software.InstallDateString}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add vulnerable software
                    html.AppendLine("    <h2>Vulnerable Software</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Version</th>");
                    html.AppendLine("            <th>Vulnerability Info</th>");
                    html.AppendLine("            <th>Vendor</th>");
                    html.AppendLine("            <th>Install Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.Vulnerable))
                    {
                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{software.Name}</td>");
                        html.AppendLine($"            <td class=\"vulnerable\">{software.Version}</td>");
                        html.AppendLine($"            <td>{software.VulnerabilityInfo}</td>");
                        html.AppendLine($"            <td>{software.Vendor}</td>");
                        html.AppendLine($"            <td>{software.InstallDateString}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");

                    // Add up-to-date software
                    html.AppendLine("    <h2>Up-to-Date Software</h2>");
                    html.AppendLine("    <table>");
                    html.AppendLine("        <tr>");
                    html.AppendLine("            <th>Name</th>");
                    html.AppendLine("            <th>Version</th>");
                    html.AppendLine("            <th>Vendor</th>");
                    html.AppendLine("            <th>Install Date</th>");
                    html.AppendLine("        </tr>");

                    foreach (var software in softwareReport.InstalledSoftware.Where(s => s.Status == SoftwareStatus.UpToDate))
                    {
                        html.AppendLine("        <tr>");
                        html.AppendLine($"            <td>{software.Name}</td>");
                        html.AppendLine($"            <td class=\"up-to-date\">{software.Version}</td>");
                        html.AppendLine($"            <td>{software.Vendor}</td>");
                        html.AppendLine($"            <td>{software.InstallDateString}</td>");
                        html.AppendLine("        </tr>");
                    }

                    html.AppendLine("    </table>");
                }

                // Add HTML footer
                html.AppendLine("    <p><em>Report generated by WinSecMonitor</em></p>");
                html.AppendLine("</body>");
                html.AppendLine("</html>");

                // Write to file
                OnReportGenerationProgress("Writing HTML file...", 80);
                await File.WriteAllTextAsync(filePath, html.ToString());

                OnReportGenerationProgress("HTML export completed", 100);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error exporting report to HTML: {ex.Message}");
                _exceptionHandler.HandleException(ex, "Error exporting report to HTML");
                throw;
            }
        }

        /// <summary>
        /// Escapes a field for CSV output
        /// </summary>
        private string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
                return string.Empty;

            bool containsSpecialChar = field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r');

            if (containsSpecialChar)
            {
                return $"\"{field.Replace("\"", "\"\"")}\"";
            }

            return field;
        }

        /// <summary>
        /// Raises the ReportGenerationProgress event
        /// </summary>
        private void OnReportGenerationProgress(string status, int percentComplete)
        {
            ReportGenerationProgress?.Invoke(this, new ReportGenerationProgressEventArgs(status, percentComplete));
        }

        /// <summary>
        /// Raises the ReportGenerationCompleted event
        /// </summary>
        private void OnReportGenerationCompleted(bool success, string errorMessage, BaseReport report)
        {
            ReportGenerationCompleted?.Invoke(this, new ReportGenerationCompletedEventArgs(success, errorMessage, report));
        }
    }

    /// <summary>
    /// Base class for all reports
    /// </summary>
    public abstract class BaseReport
    {
        public DateTime GenerationTime { get; set; }
        public string MachineName { get; set; }
        public string OperatingSystem { get; set; }
        public string UserName { get; set; }
    }

    /// <summary>
    /// Comprehensive compliance report
    /// </summary>
    public class ComplianceReport : BaseReport
    {
        // Windows update information
        public int MissingUpdatesCount { get; set; }
        public int CriticalUpdatesCount { get; set; }
        public int SecurityUpdatesCount { get; set; }
        public List<WindowsUpdate> MissingUpdates { get; set; } = new List<WindowsUpdate>();

        // Security policy information
        public int NonCompliantPoliciesCount { get; set; }
        public List<SecurityPolicy> FirewallPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> PasswordPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> AuditPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> GroupPolicies { get; set; } = new List<SecurityPolicy>();

        // Software version information
        public int OutdatedSoftwareCount { get; set; }
        public int VulnerableSoftwareCount { get; set; }
        public List<SoftwareInfo> InstalledSoftware { get; set; } = new List<SoftwareInfo>();

        // Overall compliance score
        public int ComplianceScore { get; private set; }

        /// <summary>
        /// Calculates the overall compliance score
        /// </summary>
        public void CalculateComplianceScore()
        {
            // Calculate update compliance score
            int updateScore = CalculateUpdateScore();

            // Calculate policy compliance score
            int policyScore = CalculatePolicyScore();

            // Calculate software compliance score
            int softwareScore = CalculateSoftwareScore();

            // Calculate overall compliance score (weighted average)
            ComplianceScore = (int)((updateScore * 0.4) + (policyScore * 0.4) + (softwareScore * 0.2));
        }

        /// <summary>
        /// Calculates the update compliance score
        /// </summary>
        private int CalculateUpdateScore()
        {
            if (MissingUpdatesCount == 0)
                return 100;

            // Deduct points for missing updates, with more weight on critical and security updates
            int deduction = 0;

            // Deduct for critical updates (up to 50 points)
            if (CriticalUpdatesCount > 0)
            {
                deduction += Math.Min(50, CriticalUpdatesCount * 10);
            }

            // Deduct for security updates (up to 30 points)
            if (SecurityUpdatesCount > 0)
            {
                deduction += Math.Min(30, SecurityUpdatesCount * 5);
            }

            // Deduct for other updates (up to 20 points)
            int otherUpdatesCount = MissingUpdatesCount - CriticalUpdatesCount - SecurityUpdatesCount;
            if (otherUpdatesCount > 0)
            {
                deduction += Math.Min(20, otherUpdatesCount * 2);
            }

            return Math.Max(0, 100 - deduction);
        }

        /// <summary>
        /// Calculates the policy compliance score
        /// </summary>
        private int CalculatePolicyScore()
        {
            int totalPolicies = FirewallPolicies.Count + PasswordPolicies.Count + AuditPolicies.Count + GroupPolicies.Count;

            if (totalPolicies == 0)
                return 100;

            int compliantPolicies = totalPolicies - NonCompliantPoliciesCount;
            return (int)((double)compliantPolicies / totalPolicies * 100);
        }

        /// <summary>
        /// Calculates the software compliance score
        /// </summary>
        private int CalculateSoftwareScore()
        {
            if (InstalledSoftware.Count == 0)
                return 100;

            // Count software by status
            int upToDateCount = InstalledSoftware.Count(s => s.Status == SoftwareStatus.UpToDate);

            // Calculate score based on percentage of up-to-date software
            // Vulnerable software has a higher impact on the score than outdated software
            double upToDatePercentage = (double)upToDateCount / InstalledSoftware.Count;
            int vulnerableImpact = Math.Min(40, VulnerableSoftwareCount * 8); // Up to 40 points deduction for vulnerable software
            int outdatedImpact = Math.Min(20, OutdatedSoftwareCount * 2);    // Up to 20 points deduction for outdated software

            int baseScore = (int)(upToDatePercentage * 100);
            return Math.Max(0, baseScore - vulnerableImpact - outdatedImpact);
        }
    }

    /// <summary>
    /// Windows update report
    /// </summary>
    public class WindowsUpdateReport : BaseReport
    {
        public int MissingUpdatesCount { get; set; }
        public int CriticalUpdatesCount { get; set; }
        public int SecurityUpdatesCount { get; set; }
        public List<WindowsUpdate> MissingUpdates { get; set; } = new List<WindowsUpdate>();
        public List<WindowsUpdate> InstalledUpdates { get; set; } = new List<WindowsUpdate>();
        public int UpdateComplianceScore { get; private set; }

        /// <summary>
        /// Calculates the update compliance score
        /// </summary>
        public void CalculateUpdateComplianceScore()
        {
            if (MissingUpdatesCount == 0)
            {
                UpdateComplianceScore = 100;
                return;
            }

            // Deduct points for missing updates, with more weight on critical and security updates
            int deduction = 0;

            // Deduct for critical updates (up to 50 points)
            if (CriticalUpdatesCount > 0)
            {
                deduction += Math.Min(50, CriticalUpdatesCount * 10);
            }

            // Deduct for security updates (up to 30 points)
            if (SecurityUpdatesCount > 0)
            {
                deduction += Math.Min(30, SecurityUpdatesCount * 5);
            }

            // Deduct for other updates (up to 20 points)
            int otherUpdatesCount = MissingUpdatesCount - CriticalUpdatesCount - SecurityUpdatesCount;
            if (otherUpdatesCount > 0)
            {
                deduction += Math.Min(20, otherUpdatesCount * 2);
            }

            UpdateComplianceScore = Math.Max(0, 100 - deduction);
        }
    }

    /// <summary>
    /// Security policy report
    /// </summary>
    public class SecurityPolicyReport : BaseReport
    {
        public int NonCompliantPoliciesCount { get; set; }
        public List<SecurityPolicy> FirewallPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> PasswordPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> AuditPolicies { get; set; } = new List<SecurityPolicy>();
        public List<SecurityPolicy> GroupPolicies { get; set; } = new List<SecurityPolicy>();
        public int PolicyComplianceScore { get; private set; }

        /// <summary>
        /// Calculates the policy compliance score
        /// </summary>
        public void CalculatePolicyComplianceScore()
        {
            int totalPolicies = FirewallPolicies.Count + PasswordPolicies.Count + AuditPolicies.Count + GroupPolicies.Count;

            if (totalPolicies == 0)
            {
                PolicyComplianceScore = 100;
                return;
            }

            int compliantPolicies = totalPolicies - NonCompliantPoliciesCount;
            PolicyComplianceScore = (int)((double)compliantPolicies / totalPolicies * 100);
        }
    }

    /// <summary>
    /// Software version report
    /// </summary>
    public class SoftwareVersionReport : BaseReport
    {
        public int OutdatedSoftwareCount { get; set; }
        public int VulnerableSoftwareCount { get; set; }
        public List<SoftwareInfo> InstalledSoftware { get; set; } = new List<SoftwareInfo>();
        public int SoftwareComplianceScore { get; private set; }

        /// <summary>
        /// Calculates the software compliance score
        /// </summary>
        public void CalculateSoftwareComplianceScore()
        {
            if (InstalledSoftware.Count == 0)
            {
                SoftwareComplianceScore = 100;
                return;
            }

            // Count software by status
            int upToDateCount = InstalledSoftware.Count(s => s.Status == SoftwareStatus.UpToDate);

            // Calculate score based on percentage of up-to-date software
            // Vulnerable software has a higher impact on the score than outdated software
            double upToDatePercentage = (double)upToDateCount / InstalledSoftware.Count;
            int vulnerableImpact = Math.Min(40, VulnerableSoftwareCount * 8); // Up to 40 points deduction for vulnerable software
            int outdatedImpact = Math.Min(20, OutdatedSoftwareCount * 2);    // Up to 20 points deduction for outdated software

            int baseScore = (int)(upToDatePercentage * 100);
            SoftwareComplianceScore = Math.Max(0, baseScore - vulnerableImpact - outdatedImpact);
        }
    }

    /// <summary>
    /// Event arguments for report generation progress
    /// </summary>
    public class ReportGenerationProgressEventArgs : EventArgs
    {
        public string Status { get; }
        public int PercentComplete { get; }

        public ReportGenerationProgressEventArgs(string status, int percentComplete)
        {
            Status = status;
            PercentComplete = percentComplete;
        }
    }

    /// <summary>
    /// Event arguments for report generation completed
    /// </summary>
    public class ReportGenerationCompletedEventArgs : EventArgs
    {
        public bool Success { get; }
        public string ErrorMessage { get; }
        public BaseReport Report { get; }

        public ReportGenerationCompletedEventArgs(bool success, string errorMessage, BaseReport report)
        {
            Success = success;
            ErrorMessage = errorMessage;
            Report = report;
        }
    }
}