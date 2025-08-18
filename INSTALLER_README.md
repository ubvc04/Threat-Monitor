# WinSecMonitor Installer Guide

## Overview

This document provides instructions for building and distributing the WinSecMonitor application as a standalone Windows installer.

## Prerequisites

1. **.NET 6.0 SDK** - Required to build the application
2. **NSIS (Nullsoft Scriptable Install System)** - Required to build the installer
   - Download from: https://nsis.sourceforge.io/Download
   - Make sure to add NSIS to your PATH environment variable

## Building the Installer

1. **Prepare the Environment**
   - Ensure all prerequisites are installed
   - Make sure you have the latest source code

2. **Run the Build Script**
   - Execute `build-installer.bat` from the project root directory
   - This script will:
     - Build the WinSecMonitor application in Release mode
     - Create a self-contained deployment
     - Package everything into an installer using NSIS

3. **Verify the Output**
   - After successful completion, you should find `WinSecMonitor-Setup.exe` in the project root directory

## Installer Features

- **Silent Installation**: Supports silent installation with `/S` parameter
- **Desktop Shortcut**: Creates a desktop shortcut for easy access
- **Start Menu Entry**: Adds the application to the Start Menu
- **Uninstaller**: Includes a proper uninstaller accessible from Control Panel

## Distribution

The generated installer (`WinSecMonitor-Setup.exe`) can be distributed to end users. When executed, it will:

1. Guide users through the installation process
2. Install the application to the selected directory (default: Program Files)
3. Create necessary shortcuts
4. Register the application for proper uninstallation

## Troubleshooting

- **Build Errors**: Ensure all prerequisites are correctly installed
- **NSIS Not Found**: Make sure NSIS is installed and added to your PATH
- **Installation Issues**: Check Windows Event Viewer for detailed error logs

## Customization

To customize the installer:

1. Edit `WinSecMonitor.nsi` to modify:
   - Installer appearance and branding
   - Installation directory
   - Shortcut creation
   - Registry entries

2. Rebuild using the build script