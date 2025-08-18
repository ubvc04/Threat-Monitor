# Test script for WinSecMonitor installer

# Define test parameters
$InstallerPath = "$PSScriptRoot\WinSecMonitor-Setup.exe"
$InstallDir = "C:\Program Files\WinSecMonitor"
$DesktopShortcut = "$env:USERPROFILE\Desktop\WinSecMonitor.lnk"
$StartMenuShortcut = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\WinSecMonitor\WinSecMonitor.lnk"
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Windows Security Monitor"

# Function to check if a file or directory exists
function Test-PathExists {
    param (
        [string]$Path,
        [string]$Description
    )
    
    if (Test-Path -Path $Path) {
        Write-Host "[PASS] $Description exists at: $Path" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[FAIL] $Description does not exist at: $Path" -ForegroundColor Red
        return $false
    }
}

# Function to check if registry key exists
function Test-RegistryKeyExists {
    param (
        [string]$Key,
        [string]$Description
    )
    
    if (Test-Path -Path $Key) {
        Write-Host "[PASS] $Description exists at: $Key" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[FAIL] $Description does not exist at: $Key" -ForegroundColor Red
        return $false
    }
}

# Function to simulate installation test
function Test-Installation {
    Write-Host "\n=== Testing Installation ===" -ForegroundColor Cyan
    
    # Check if installer exists
    if (-not (Test-PathExists -Path $InstallerPath -Description "Installer executable")) {
        Write-Host "Cannot proceed with installation test. Installer not found." -ForegroundColor Red
        return $false
    }
    
    Write-Host "Simulating installation process..." -ForegroundColor Yellow
    # In a real test, we would run the installer here
    # & $InstallerPath /S
    
    # Check installation results
    $installationSuccess = $true
    $installationSuccess = $installationSuccess -and (Test-PathExists -Path $InstallDir -Description "Installation directory")
    $installationSuccess = $installationSuccess -and (Test-PathExists -Path "$InstallDir\WinSecMonitor.exe" -Description "Main executable")
    $installationSuccess = $installationSuccess -and (Test-PathExists -Path $DesktopShortcut -Description "Desktop shortcut")
    $installationSuccess = $installationSuccess -and (Test-PathExists -Path $StartMenuShortcut -Description "Start Menu shortcut")
    $installationSuccess = $installationSuccess -and (Test-RegistryKeyExists -Key $UninstallKey -Description "Uninstall registry key")
    
    if ($installationSuccess) {
        Write-Host "Installation test completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Installation test failed." -ForegroundColor Red
    }
    
    return $installationSuccess
}

# Function to simulate uninstallation test
function Test-Uninstallation {
    Write-Host "\n=== Testing Uninstallation ===" -ForegroundColor Cyan
    
    Write-Host "Simulating uninstallation process..." -ForegroundColor Yellow
    # In a real test, we would run the uninstaller here
    # & "$InstallDir\uninstall.exe" /S
    
    # Check uninstallation results
    $uninstallationSuccess = $true
    $uninstallationSuccess = $uninstallationSuccess -and (-not (Test-Path -Path $InstallDir))
    $uninstallationSuccess = $uninstallationSuccess -and (-not (Test-Path -Path $DesktopShortcut))
    $uninstallationSuccess = $uninstallationSuccess -and (-not (Test-Path -Path $StartMenuShortcut))
    $uninstallationSuccess = $uninstallationSuccess -and (-not (Test-Path -Path $UninstallKey))
    
    if ($uninstallationSuccess) {
        Write-Host "Uninstallation test completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Uninstallation test failed." -ForegroundColor Red
    }
    
    return $uninstallationSuccess
}

# Main test execution
Write-Host "=== WinSecMonitor Installer Test Script ===" -ForegroundColor Cyan
Write-Host "This script simulates testing the installation and uninstallation process." -ForegroundColor Yellow
Write-Host "In a real environment, it would actually install and uninstall the application." -ForegroundColor Yellow

# Run tests
$installSuccess = Test-Installation

if ($installSuccess) {
    $uninstallSuccess = Test-Uninstallation
    
    if ($uninstallSuccess) {
        Write-Host "\n[OVERALL RESULT] All tests passed successfully." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "\n[OVERALL RESULT] Uninstallation test failed." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "\n[OVERALL RESULT] Installation test failed." -ForegroundColor Red
    exit 1
}