# WinSecMonitor Installer Script
# NSIS (Nullsoft Scriptable Install System) Script

# Define constants
!define PRODUCT_NAME "Windows Security Monitor"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "WinSecMonitor Team"
!define PRODUCT_WEB_SITE "https://winsecmonitor.example.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\WinSecMonitor.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

# Include Modern UI
!include "MUI2.nsh"

# Set compression
SetCompressor lzma

# General settings
Name "${PRODUCT_NAME}"
OutFile "WinSecMonitor-Setup.exe"
InstallDir "$PROGRAMFILES\WinSecMonitor"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

# MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "WinSecMonitor\Resources\app.ico"
!define MUI_UNICON "WinSecMonitor\Resources\app.ico"

# Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

# Language files
!insertmacro MUI_LANGUAGE "English"

# Installer sections
Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  
  # Copy application files
  File /r "WinSecMonitor\bin\Release\net6.0-windows10.0.19041.0\publish\*.*"
  
  # Create shortcuts
  CreateDirectory "$SMPROGRAMS\WinSecMonitor"
  CreateShortCut "$SMPROGRAMS\WinSecMonitor\WinSecMonitor.lnk" "$INSTDIR\WinSecMonitor.exe"
  CreateShortCut "$DESKTOP\WinSecMonitor.lnk" "$INSTDIR\WinSecMonitor.exe"
  
  # Write registry keys for uninstaller
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\WinSecMonitor.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\WinSecMonitor.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  
  # Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

# Uninstaller section
Section Uninstall
  # Remove shortcuts
  Delete "$SMPROGRAMS\WinSecMonitor\WinSecMonitor.lnk"
  Delete "$DESKTOP\WinSecMonitor.lnk"
  RMDir "$SMPROGRAMS\WinSecMonitor"
  
  # Remove files and directories
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR"
  
  # Remove registry keys
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd