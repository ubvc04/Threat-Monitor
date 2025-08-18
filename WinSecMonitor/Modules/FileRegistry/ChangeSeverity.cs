namespace WinSecMonitor.Modules.FileRegistry
{
    /// <summary>
    /// Represents the severity level of a file or registry change
    /// </summary>
    public enum ChangeSeverity
    {
        /// <summary>
        /// Low severity change - informational, not likely to be malicious
        /// </summary>
        Low = 0,

        /// <summary>
        /// Medium severity change - potentially suspicious, requires attention
        /// </summary>
        Medium = 1,

        /// <summary>
        /// High severity change - likely malicious, requires immediate attention
        /// </summary>
        High = 2
    }
}