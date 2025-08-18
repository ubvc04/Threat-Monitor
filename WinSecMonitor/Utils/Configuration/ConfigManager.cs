using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using WinSecMonitor.Utils.Logging;

namespace WinSecMonitor.Utils.Configuration
{
    public class ConfigManager
    {
        private static readonly Lazy<ConfigManager> _instance = new Lazy<ConfigManager>(() => new ConfigManager());
        private readonly string _configFilePath;
        private Dictionary<string, object> _settings;
        private readonly object _lockObject = new object();

        public static ConfigManager Instance => _instance.Value;

        private ConfigManager()
        {
            string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSecMonitor");
            if (!Directory.Exists(appDataPath))
            {
                Directory.CreateDirectory(appDataPath);
            }

            _configFilePath = Path.Combine(appDataPath, "config.json");
            LoadConfiguration();
        }

        private void LoadConfiguration()
        {
            try
            {
                if (File.Exists(_configFilePath))
                {
                    string json = File.ReadAllText(_configFilePath);
                    _settings = JsonSerializer.Deserialize<Dictionary<string, object>>(json) ?? new Dictionary<string, object>();
                }
                else
                {
                    _settings = new Dictionary<string, object>();
                    SaveConfiguration(); // Create default config file
                }

                Logger.Instance.LogInformation("Configuration loaded successfully");
            }
            catch (Exception ex)
            {
                Logger.Instance.LogException(ex, "Failed to load configuration");
                _settings = new Dictionary<string, object>(); // Use empty settings on error
            }
        }

        public void SaveConfiguration()
        {
            try
            {
                lock (_lockObject)
                {
                    string json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_configFilePath, json);
                }

                Logger.Instance.LogInformation("Configuration saved successfully");
            }
            catch (Exception ex)
            {
                Logger.Instance.LogException(ex, "Failed to save configuration");
            }
        }

        public T GetSetting<T>(string key, T defaultValue = default)
        {
            lock (_lockObject)
            {
                if (_settings.TryGetValue(key, out object value))
                {
                    try
                    {
                        // Handle conversion from JsonElement to the target type
                        if (value is JsonElement element)
                        {
                            return (T)Convert.ChangeType(element.GetRawText(), typeof(T));
                        }
                        return (T)value;
                    }
                    catch
                    {
                        Logger.Instance.LogWarning($"Failed to convert setting '{key}' to type {typeof(T).Name}");
                        return defaultValue;
                    }
                }
                return defaultValue;
            }
        }

        public void SetSetting<T>(string key, T value)
        {
            lock (_lockObject)
            {
                _settings[key] = value;
            }
        }

        public bool HasSetting(string key)
        {
            lock (_lockObject)
            {
                return _settings.ContainsKey(key);
            }
        }

        public void RemoveSetting(string key)
        {
            lock (_lockObject)
            {
                if (_settings.ContainsKey(key))
                {
                    _settings.Remove(key);
                }
            }
        }

        public async Task SaveConfigurationAsync()
        {
            try
            {
                string json;
                lock (_lockObject)
                {
                    json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                }

                await File.WriteAllTextAsync(_configFilePath, json);
                Logger.Instance.LogInformation("Configuration saved asynchronously");
            }
            catch (Exception ex)
            {
                Logger.Instance.LogException(ex, "Failed to save configuration asynchronously");
            }
        }
    }
}