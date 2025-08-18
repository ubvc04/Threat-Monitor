@echo off
echo Building WinSecMonitor application...

:: Set variables
set PROJECT_DIR=%~dp0WinSecMonitor
set OUTPUT_DIR=%PROJECT_DIR%\bin\Release\net6.0-windows10.0.19041.0\publish

:: Build the application in Release mode with self-contained deployment
echo Building .NET application...
dotnet publish "%PROJECT_DIR%\WinSecMonitor.csproj" -c Release --self-contained true -r win-x64 -p:PublishSingleFile=true -p:PublishTrimmed=true

if %ERRORLEVEL% NEQ 0 (
    echo Error building the application.
    exit /b %ERRORLEVEL%
)

echo Application built successfully.

:: Check if NSIS is installed
where makensis >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo NSIS (Nullsoft Scriptable Install System) is not installed or not in PATH.
    echo Please install NSIS from https://nsis.sourceforge.io/Download
    echo After installation, add the NSIS directory to your PATH environment variable.
    exit /b 1
)

:: Build the installer
echo Building installer...
makensis WinSecMonitor.nsi

if %ERRORLEVEL% NEQ 0 (
    echo Error building the installer.
    exit /b %ERRORLEVEL%
)

echo Installer built successfully: %~dp0WinSecMonitor-Setup.exe