# WinSecMonitor

A comprehensive Windows security monitoring application built with C# and WPF. This application provides real-time monitoring of system security, user activities, file/registry changes, processes, network connections, vulnerabilities, and compliance status.

## Features

- **System Monitoring**: Track system resources, performance metrics, and security events
- **User Activity Monitoring**: Monitor user logins, permissions changes, and suspicious activities
- **File/Registry Monitoring**: Watch for changes to critical files and registry keys
- **Process Monitoring**: Track running processes and detect suspicious behavior
- **Network Monitoring**: Monitor network connections and detect unusual traffic patterns
- **Vulnerability Assessment**: Identify and report potential security vulnerabilities
- **Compliance Checking**: Verify system compliance with security policies and standards
- **Alert & Mitigation Engine**: Receive alerts and automated mitigation recommendations
- **Event Correlation**: Correlate events across different monitoring modules
- **Custom Rules**: Create and manage custom security rules

## System Requirements

- Windows 10 (version 1809 or later) or Windows 11
- .NET 6.0 Runtime or later
- Administrator privileges (required for certain monitoring features)
- Minimum 4GB RAM
- 100MB free disk space

## Project Structure

```
WinSecMonitor/
├── Modules/                # Monitoring modules
│   ├── System/            # System monitoring
│   ├── User/              # User activity monitoring
│   ├── FileRegistry/      # File and registry monitoring
│   ├── Processes/         # Process monitoring
│   ├── Network/           # Network monitoring
│   ├── Vulnerabilities/   # Vulnerability assessment
│   └── Compliance/        # Compliance checking
├── Engine/                # Core engine components
│   ├── Alert/             # Alert generation and management
│   ├── Mitigation/        # Automated mitigation recommendations
│   ├── EventCorrelation/  # Event correlation engine
│   └── CustomRules/       # Custom security rules
├── GUI/                   # User interface components
│   ├── Views/             # MVVM views
│   ├── Windows/           # Window definitions
│   └── XAML/              # XAML resources
└── Utils/                 # Utility components
    ├── Logging/           # Logging framework
    ├── Configuration/     # Configuration management
    └── ErrorHandling/     # Global error handling
```

## Building the Application

### Prerequisites

- Visual Studio 2022 or later (Community, Professional, or Enterprise)
- .NET 6.0 SDK or later
- Windows 10/11 SDK

### Build Steps

1. Clone the repository or download the source code

```powershell
git clone https://github.com/yourusername/WinSecMonitor.git
cd WinSecMonitor
```

2. Open the solution in Visual Studio

```powershell
start WinSecMonitor.sln
```

3. Restore NuGet packages

```powershell
dotnet restore
```

4. Build the solution

```powershell
dotnet build
```

5. Run the application

```powershell
dotnet run
```

### Building from Command Line

```powershell
# Restore packages
dotnet restore

# Build in Debug mode
dotnet build

# Build in Release mode
dotnet build -c Release

# Publish the application
dotnet publish -c Release -r win-x64 --self-contained
```

## Running the Application

### From Visual Studio

1. Set WinSecMonitor as the startup project
2. Press F5 or click the "Start" button
3. Accept the UAC prompt (the application requires administrator privileges)

### From Command Line

```powershell
# Run from the build output directory
cd bin\Debug\net6.0-windows10.0.19041.0
WinSecMonitor.exe

# Or use dotnet run from the project directory
dotnet run
```

### From Published Build

```powershell
cd bin\Release\net6.0-windows10.0.19041.0\win-x64\publish
WinSecMonitor.exe
```

## Testing

### Running Unit Tests

```powershell
dotnet test
```

### Manual Testing Checklist

1. **Installation Test**
   - Verify the application installs correctly
   - Check that all required dependencies are installed

2. **Startup Test**
   - Verify the application starts without errors
   - Check that the UAC prompt appears and works correctly

3. **Module Tests**
   - Test each monitoring module individually
   - Verify that data is collected and displayed correctly

4. **Alert Tests**
   - Trigger test alerts to verify the alert system
   - Check that notifications appear correctly

5. **Performance Tests**
   - Monitor CPU and memory usage during operation
   - Verify the application remains responsive during heavy monitoring

## Troubleshooting

### Common Issues

1. **Application fails to start with administrative privileges**
   - Verify that you're running as an administrator
   - Check the application manifest settings

2. **Modules not loading correctly**
   - Check the application logs in `%LocalAppData%\WinSecMonitor\application.log`
   - Verify that all dependencies are installed

3. **High CPU or memory usage**
   - Adjust the monitoring frequency in the settings
   - Disable modules that aren't needed

### Logging

The application logs are stored in:

```
%LocalAppData%\WinSecMonitor\application.log
```

The configuration file is stored in:

```
%LocalAppData%\WinSecMonitor\config.json
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.