using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinSecMonitor.Modules.Processes
{
    /// <summary>
    /// Analyzes process behavior to detect unusual patterns
    /// </summary>
    public class ProcessBehaviorAnalyzer
    {
        #region Private Fields

        private readonly Dictionary<int, ProcessBehaviorData> _processBehaviorData;
        private readonly Dictionary<string, ProcessSpawningData> _processSpawningData;
        private readonly HashSet<string> _knownGoodParentProcesses;
        private readonly object _lockObject = new object();

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the ProcessBehaviorAnalyzer class
        /// </summary>
        public ProcessBehaviorAnalyzer()
        {
            _processBehaviorData = new Dictionary<int, ProcessBehaviorData>();
            _processSpawningData = new Dictionary<string, ProcessSpawningData>(StringComparer.OrdinalIgnoreCase);
            _knownGoodParentProcesses = InitializeKnownGoodParentProcesses();

            LogInfo("ProcessBehaviorAnalyzer initialized");
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Analyzes a process for unusual behavior
        /// </summary>
        /// <param name="processInfo">The process information to analyze</param>
        /// <returns>Analysis result with details about any unusual behavior</returns>
        public ProcessBehaviorResult AnalyzeProcess(ProcessInfo processInfo)
        {
            if (processInfo == null)
            {
                return null;
            }

            lock (_lockObject)
            {
                // Get or create behavior data for this process
                if (!_processBehaviorData.TryGetValue(processInfo.Id, out var behaviorData))
                {
                    behaviorData = new ProcessBehaviorData
                    {
                        ProcessId = processInfo.Id,
                        ProcessName = processInfo.Name,
                        FirstSeen = DateTime.Now,
                        LastSeen = DateTime.Now,
                        ParentProcessId = processInfo.ParentProcessId,
                        Path = processInfo.Path,
                        MemoryUsageHistory = new List<double>(),
                        CpuUsageHistory = new List<double>()
                    };

                    _processBehaviorData.Add(processInfo.Id, behaviorData);
                }

                // Update behavior data
                behaviorData.LastSeen = DateTime.Now;
                behaviorData.MemoryUsageHistory.Add(processInfo.MemoryUsageMB);
                behaviorData.CpuUsageHistory.Add(processInfo.CpuUsagePercent);

                // Keep history limited to prevent memory growth
                if (behaviorData.MemoryUsageHistory.Count > 10)
                {
                    behaviorData.MemoryUsageHistory.RemoveAt(0);
                }

                if (behaviorData.CpuUsageHistory.Count > 10)
                {
                    behaviorData.CpuUsageHistory.RemoveAt(0);
                }

                // Analyze for unusual behavior
                var result = new ProcessBehaviorResult
                {
                    ProcessId = processInfo.Id,
                    ProcessName = processInfo.Name,
                    IsUnusual = false
                };

                // Check for unusual resource usage
                if (IsUnusualResourceUsage(behaviorData))
                {
                    result.IsUnusual = true;
                    result.UnusualBehaviors.Add("Unusual resource usage pattern");
                }

                // Check for unusual process spawning
                if (processInfo.ParentProcessId > 0)
                {
                    var spawningResult = AnalyzeProcessSpawning(processInfo.Name, processInfo.ParentProcessId);
                    if (spawningResult.IsUnusual)
                    {
                        result.IsUnusual = true;
                        result.UnusualBehaviors.AddRange(spawningResult.UnusualBehaviors);
                    }
                }

                // Check for unusual execution location
                if (IsUnusualExecutionLocation(processInfo.Path))
                {
                    result.IsUnusual = true;
                    result.UnusualBehaviors.Add("Unusual execution location");
                }

                return result;
            }
        }

        /// <summary>
        /// Records a process start event for spawning analysis
        /// </summary>
        /// <param name="childName">The name of the child process</param>
        /// <param name="parentId">The ID of the parent process</param>
        /// <param name="parentName">The name of the parent process</param>
        public void RecordProcessStart(string childName, int parentId, string parentName)
        {
            if (string.IsNullOrEmpty(childName) || string.IsNullOrEmpty(parentName))
            {
                return;
            }

            lock (_lockObject)
            {
                // Record parent-child relationship
                if (!_processSpawningData.TryGetValue(parentName, out var spawningData))
                {
                    spawningData = new ProcessSpawningData
                    {
                        ParentProcessName = parentName,
                        ChildProcesses = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
                        SpawnCount = 0,
                        LastSpawnTime = DateTime.MinValue
                    };

                    _processSpawningData.Add(parentName, spawningData);
                }

                // Update spawn count for this child
                if (spawningData.ChildProcesses.TryGetValue(childName, out var count))
                {
                    spawningData.ChildProcesses[childName] = count + 1;
                }
                else
                {
                    spawningData.ChildProcesses.Add(childName, 1);
                }

                // Update overall spawn count and time
                spawningData.SpawnCount++;
                
                // Calculate spawn rate if we have previous spawn time
                if (spawningData.LastSpawnTime != DateTime.MinValue)
                {
                    var timeSinceLastSpawn = DateTime.Now - spawningData.LastSpawnTime;
                    spawningData.RecentSpawnRates.Add(timeSinceLastSpawn.TotalSeconds);
                    
                    // Keep history limited
                    if (spawningData.RecentSpawnRates.Count > 10)
                    {
                        spawningData.RecentSpawnRates.RemoveAt(0);
                    }
                }
                
                spawningData.LastSpawnTime = DateTime.Now;
            }
        }

        /// <summary>
        /// Clears the behavior data for a process
        /// </summary>
        /// <param name="processId">The ID of the process</param>
        public void ClearProcessData(int processId)
        {
            lock (_lockObject)
            {
                _processBehaviorData.Remove(processId);
            }
        }

        /// <summary>
        /// Clears all behavior data
        /// </summary>
        public void ClearAllData()
        {
            lock (_lockObject)
            {
                _processBehaviorData.Clear();
                _processSpawningData.Clear();
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the set of known good parent processes
        /// </summary>
        private HashSet<string> InitializeKnownGoodParentProcesses()
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer", "services", "svchost", "wininit", "winlogon",
                "smss", "csrss", "lsass", "taskhost", "taskhostw",
                "userinit", "dwm", "conhost", "cmd", "powershell",
                "msiexec", "installerservice", "setup", "mmc", "rundll32",
                "dllhost", "taskeng", "taskmgr", "wmiprvse", "spoolsv",
                "searchindexer", "searchprotocolhost", "searchfilterhost",
                "wuauclt", "trustedinstaller", "devenv", "msbuild", "dotnet",
                "node", "npm", "yarn", "java", "javaw", "chrome", "firefox",
                "iexplore", "microsoftedge", "msedge", "outlook", "winword",
                "excel", "powerpnt", "onenote", "teams", "skype", "zoom"
            };
        }

        /// <summary>
        /// Analyzes process spawning behavior
        /// </summary>
        private ProcessBehaviorResult AnalyzeProcessSpawning(string childName, int parentId)
        {
            var result = new ProcessBehaviorResult
            {
                IsUnusual = false,
                UnusualBehaviors = new List<string>()
            };

            // Get parent process name
            string parentName = "Unknown";
            if (_processBehaviorData.TryGetValue(parentId, out var parentData))
            {
                parentName = parentData.ProcessName;
            }

            // Check if this is an unusual parent-child relationship
            if (!IsKnownGoodParent(parentName))
            {
                result.IsUnusual = true;
                result.UnusualBehaviors.Add($"Unusual parent process: {parentName}");
            }

            // Check for rapid spawning
            if (_processSpawningData.TryGetValue(parentName, out var spawningData))
            {
                // Check if parent has spawned many processes recently
                if (spawningData.SpawnCount > 10 && spawningData.RecentSpawnRates.Count > 5)
                {
                    // Calculate average spawn rate
                    double avgSpawnRate = spawningData.RecentSpawnRates.Average();
                    
                    // If spawning more than 1 process per second on average
                    if (avgSpawnRate < 1.0)
                    {
                        result.IsUnusual = true;
                        result.UnusualBehaviors.Add($"Rapid process spawning from {parentName}");
                    }
                }

                // Check for unusual diversity of child processes
                if (spawningData.ChildProcesses.Count > 5)
                {
                    result.IsUnusual = true;
                    result.UnusualBehaviors.Add($"Unusual diversity of child processes from {parentName}");
                }
            }

            return result;
        }

        /// <summary>
        /// Checks if a process is showing unusual resource usage patterns
        /// </summary>
        private bool IsUnusualResourceUsage(ProcessBehaviorData behaviorData)
        {
            if (behaviorData.MemoryUsageHistory.Count < 3 || behaviorData.CpuUsageHistory.Count < 3)
            {
                return false;
            }

            // Check for sudden memory spikes
            double memoryAvg = behaviorData.MemoryUsageHistory.Take(behaviorData.MemoryUsageHistory.Count - 1).Average();
            double currentMemory = behaviorData.MemoryUsageHistory.Last();
            if (currentMemory > memoryAvg * 2 && currentMemory > 100) // More than double and > 100MB
            {
                return true;
            }

            // Check for sudden CPU spikes
            double cpuAvg = behaviorData.CpuUsageHistory.Take(behaviorData.CpuUsageHistory.Count - 1).Average();
            double currentCpu = behaviorData.CpuUsageHistory.Last();
            if (currentCpu > cpuAvg * 2 && currentCpu > 50) // More than double and > 50%
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if a process is running from an unusual location
        /// </summary>
        private bool IsUnusualExecutionLocation(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }

            // Check for execution from temp directories
            string pathLower = path.ToLowerInvariant();
            if (pathLower.Contains("\\temp\\") ||
                pathLower.Contains("\\tmp\\") ||
                pathLower.Contains("\\appdata\\local\\temp") ||
                pathLower.Contains("\\windows\\temp") ||
                pathLower.Contains("\\programdata\\temp") ||
                pathLower.Contains("\\users\\public\\") ||
                pathLower.Contains("\\recycle"))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if a process is a known good parent process
        /// </summary>
        private bool IsKnownGoodParent(string processName)
        {
            return _knownGoodParentProcesses.Contains(processName);
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        private static void LogInfo(string message)
        {
            // TODO: Replace with actual logging implementation
            Console.WriteLine($"[INFO] [ProcessBehaviorAnalyzer] {message}");
        }

        #endregion
    }

    /// <summary>
    /// Represents behavior data for a process
    /// </summary>
    internal class ProcessBehaviorData
    {
        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets when the process was first seen
        /// </summary>
        public DateTime FirstSeen { get; set; }

        /// <summary>
        /// Gets or sets when the process was last seen
        /// </summary>
        public DateTime LastSeen { get; set; }

        /// <summary>
        /// Gets or sets the parent process ID
        /// </summary>
        public int ParentProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process file path
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Gets or sets the memory usage history
        /// </summary>
        public List<double> MemoryUsageHistory { get; set; }

        /// <summary>
        /// Gets or sets the CPU usage history
        /// </summary>
        public List<double> CpuUsageHistory { get; set; }
    }

    /// <summary>
    /// Represents process spawning data for a parent process
    /// </summary>
    internal class ProcessSpawningData
    {
        /// <summary>
        /// Gets or sets the parent process name
        /// </summary>
        public string ParentProcessName { get; set; }

        /// <summary>
        /// Gets or sets the child processes and their spawn counts
        /// </summary>
        public Dictionary<string, int> ChildProcesses { get; set; }

        /// <summary>
        /// Gets or sets the total spawn count
        /// </summary>
        public int SpawnCount { get; set; }

        /// <summary>
        /// Gets or sets the last spawn time
        /// </summary>
        public DateTime LastSpawnTime { get; set; }

        /// <summary>
        /// Gets or sets the recent spawn rates in seconds between spawns
        /// </summary>
        public List<double> RecentSpawnRates { get; set; } = new List<double>();
    }

    /// <summary>
    /// Represents the result of analyzing process behavior
    /// </summary>
    public class ProcessBehaviorResult
    {
        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Gets or sets the process name
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Gets or sets whether the process behavior is unusual
        /// </summary>
        public bool IsUnusual { get; set; }

        /// <summary>
        /// Gets or sets the list of unusual behaviors
        /// </summary>
        public List<string> UnusualBehaviors { get; set; } = new List<string>();
    }
}