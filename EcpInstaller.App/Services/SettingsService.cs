using EcpInstaller.App.Models;
using System.IO;
using System.Text.Json;

namespace EcpInstaller.App.Services;

public sealed class SettingsService
{
    private const string FileName = "config.json";

    public (AppSettings Settings, string Path) Load(AppLogger logger)
    {
        var path = ResolveWritableConfigPath();
        if (!File.Exists(path))
        {
            return (new AppSettings(), path);
        }

        try
        {
            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            logger.Info($"settings loaded: {path}");
            return (settings, path);
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось загрузить настройки, используются значения по умолчанию: {ex.Message}");
            return (new AppSettings(), path);
        }
    }

    public void Save(AppSettings settings, string? currentPath, AppLogger logger)
    {
        var path = string.IsNullOrWhiteSpace(currentPath) ? ResolveWritableConfigPath() : currentPath;

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
            logger.Info($"Настройки сохранены: {path}");
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось сохранить настройки: {ex.Message}");
        }
    }

    private static string ResolveWritableConfigPath()
    {
        var exePath = Path.Combine(AppContext.BaseDirectory, FileName);
        try
        {
            if (!File.Exists(exePath))
            {
                File.WriteAllText(exePath, "{}");
            }
            else
            {
                using var _ = File.Open(exePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            }
            return exePath;
        }
        catch
        {
            var appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "EcpInstaller", FileName);
            return appDataPath;
        }
    }
}
