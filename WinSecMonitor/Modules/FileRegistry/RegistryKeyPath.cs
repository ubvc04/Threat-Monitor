using System;
using Microsoft.Win32;

namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Represents a registry key path for monitoring
    /// </summary>
    public class RegistryKeyPath
    {
        #region Properties

        /// <summary>
        /// The registry hive (HKLM, HKCU, etc.)
        /// </summary>
        public RegistryHive Hive { get; set; }

        /// <summary>
        /// The subkey path under the hive
        /// </summary>
        public string SubKeyPath { get; set; }

        /// <summary>
        /// Whether to include subkeys in monitoring
        /// </summary>
        public bool IncludeSubKeys { get; set; }

        /// <summary>
        /// Gets the full registry path including hive
        /// </summary>
        public string FullPath
        {
            get
            {
                string hiveString = GetHiveString(Hive);
                return $"{hiveString}\\{SubKeyPath}";
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the RegistryKeyPath class
        /// </summary>
        public RegistryKeyPath()
        {
            IncludeSubKeys = true;
        }

        /// <summary>
        /// Initializes a new instance of the RegistryKeyPath class with specified hive and subkey path
        /// </summary>
        /// <param name="hive">The registry hive</param>
        /// <param name="subKeyPath">The subkey path under the hive</param>
        /// <param name="includeSubKeys">Whether to include subkeys in monitoring</param>
        public RegistryKeyPath(RegistryHive hive, string subKeyPath, bool includeSubKeys = true)
        {
            Hive = hive;
            SubKeyPath = subKeyPath;
            IncludeSubKeys = includeSubKeys;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Creates a RegistryKeyPath from a full registry path string
        /// </summary>
        /// <param name="fullPath">The full registry path (e.g., "HKLM\SOFTWARE\Microsoft\Windows")</param>
        /// <returns>A new RegistryKeyPath instance</returns>
        public static RegistryKeyPath FromString(string fullPath)
        {
            if (string.IsNullOrWhiteSpace(fullPath))
                throw new ArgumentException("Path cannot be null or empty", nameof(fullPath));

            // Split the path into hive and subkey parts
            int separatorIndex = fullPath.IndexOf('\\');
            if (separatorIndex <= 0)
                throw new ArgumentException("Invalid registry path format", nameof(fullPath));

            string hiveString = fullPath.Substring(0, separatorIndex);
            string subKeyPath = fullPath.Substring(separatorIndex + 1);

            // Parse the hive
            RegistryHive hive = ParseHiveString(hiveString);

            return new RegistryKeyPath(hive, subKeyPath);
        }

        /// <summary>
        /// Returns a string representation of the registry key path
        /// </summary>
        public override string ToString()
        {
            return FullPath;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object
        /// </summary>
        public override bool Equals(object obj)
        {
            if (obj is RegistryKeyPath other)
            {
                return Hive == other.Hive && 
                       string.Equals(SubKeyPath, other.SubKeyPath, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        /// <summary>
        /// Returns the hash code for this instance
        /// </summary>
        public override int GetHashCode()
        {
            return HashCode.Combine(Hive, SubKeyPath?.ToLowerInvariant());
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Gets the string representation of a registry hive
        /// </summary>
        private string GetHiveString(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:
                    return "HKCR";
                case RegistryHive.CurrentUser:
                    return "HKCU";
                case RegistryHive.LocalMachine:
                    return "HKLM";
                case RegistryHive.Users:
                    return "HKU";
                case RegistryHive.CurrentConfig:
                    return "HKCC";
                default:
                    return hive.ToString();
            }
        }

        /// <summary>
        /// Parses a string representation of a registry hive
        /// </summary>
        private static RegistryHive ParseHiveString(string hiveString)
        {
            switch (hiveString.ToUpperInvariant())
            {
                case "HKCR":
                case "HKEY_CLASSES_ROOT":
                    return RegistryHive.ClassesRoot;
                case "HKCU":
                case "HKEY_CURRENT_USER":
                    return RegistryHive.CurrentUser;
                case "HKLM":
                case "HKEY_LOCAL_MACHINE":
                    return RegistryHive.LocalMachine;
                case "HKU":
                case "HKEY_USERS":
                    return RegistryHive.Users;
                case "HKCC":
                case "HKEY_CURRENT_CONFIG":
                    return RegistryHive.CurrentConfig;
                default:
                    throw new ArgumentException($"Unknown registry hive: {hiveString}");
            }
        }

        #endregion
    }
}