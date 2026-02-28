using System.Collections.ObjectModel;
using System.IO;

namespace EcpInstaller.App.Services;

public sealed class AppLogger
{
    private readonly string _logPath;
    private readonly object _sync = new();

    public AppLogger(string appDirectory)
    {
        _logPath = Path.Combine(appDirectory, "EcpInstaller.log");
        StartNewSession();
    }

    /// <summary>Начинает новую сессию: очищает лог в интерфейсе и файл (в файле только текущий запуск).</summary>
    public void StartNewSession()
    {
        var header = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [INFO] Сессия запущена.";
        lock (_sync)
        {
            try
            {
                File.WriteAllText(_logPath, header + Environment.NewLine);
            }
            catch { /* файл может быть занят */ }
        }

        App.Current.Dispatcher.Invoke(() =>
        {
            UiLogs.Clear();
            UiLogs.Add(header);
        });
    }

    public ObservableCollection<string> UiLogs { get; } = [];

    public string LogPath => _logPath;

    public void Info(string message) => Write("INFO", message);

    public void Warn(string message) => Write("WARN", message);

    public void Error(string message) => Write("ERROR", message);

    private void Write(string level, string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";

        lock (_sync)
        {
            File.AppendAllText(_logPath, line + Environment.NewLine);
        }

        App.Current.Dispatcher.Invoke(() =>
        {
            UiLogs.Add(line);
            if (UiLogs.Count > 500)
            {
                UiLogs.RemoveAt(0);
            }
        });
    }
}
