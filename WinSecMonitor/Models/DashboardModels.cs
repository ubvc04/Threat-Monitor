using System;
using System.Windows.Media;

namespace WinSecMonitor.Models
{
    /// <summary>
    /// Represents an alert in the system
    /// </summary>
    public class Alert
    {
        /// <summary>
        /// Gets or sets the timestamp of the alert
        /// </summary>
        public DateTime Timestamp { get; set; }
        
        /// <summary>
        /// Gets or sets the module that generated the alert
        /// </summary>
        public string Module { get; set; }
        
        /// <summary>
        /// Gets or sets the severity of the alert (Low, Medium, High, Critical)
        /// </summary>
        public string Severity { get; set; }
        
        /// <summary>
        /// Gets or sets the description of the alert
        /// </summary>
        public string Description { get; set; }
    }
    
    /// <summary>
    /// Represents the status of a monitoring module
    /// </summary>
    public class ModuleStatus
    {
        /// <summary>
        /// Gets or sets the name of the module
        /// </summary>
        public string Name { get; set; }
        
        /// <summary>
        /// Gets or sets the status of the module (Active, Warning, Inactive, Error)
        /// </summary>
        public string Status { get; set; }
        
        /// <summary>
        /// Gets or sets the color representing the status
        /// </summary>
        public Brush StatusColor { get; set; }
        
        /// <summary>
        /// Gets or sets when the module was last updated
        /// </summary>
        public string LastUpdated { get; set; }
    }
    
    /// <summary>
    /// Represents a security recommendation for the system
    /// </summary>
    public class SecurityRecommendation
    {
        /// <summary>
        /// Gets or sets the description of the recommendation
        /// </summary>
        public string Description { get; set; }
        
        /// <summary>
        /// Gets or sets the priority color (Red for high, Orange for medium, Yellow for low)
        /// </summary>
        public Brush PriorityColor { get; set; }
        
        /// <summary>
        /// Gets or sets whether the recommendation can be automatically fixed
        /// </summary>
        public bool CanAutoFix { get; set; }
    }
}