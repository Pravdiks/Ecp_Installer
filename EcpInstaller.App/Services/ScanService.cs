using EcpInstaller.App.Models;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EcpInstaller.App.Services;

public sealed class ScanService
{
    private static readonly HashSet<string> PfxExtensions = [".pfx", ".p12"];
    private static readonly HashSet<string> CertExtensions = [".cer", ".crt"];

    public IReadOnlyCollection<SignatureTask> Scan(IEnumerable<string> inputPaths, AppLogger logger, bool onlyMostActual, string pfxPassword)
    {
        var files = ExpandFiles(inputPaths, logger).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var tasks = new List<SignatureTask>();
        var candidates = new List<ScanCandidate>();

        foreach (var file in files)
        {
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (PfxExtensions.Contains(ext))
            {
                var pfxCandidate = BuildPfxCandidate(file, pfxPassword, logger);
                candidates.Add(pfxCandidate);
                continue;
            }

            if (!CertExtensions.Contains(ext))
            {
                continue;
            }

            var candidate = BuildCerCandidate(file, logger);
            candidates.Add(candidate);
        }

        if (onlyMostActual)
        {
            ApplyMostActualRule(candidates, logger);
        }

        foreach (var candidate in candidates)
        {
            var task = new SignatureTask
            {
                Kind = candidate.Kind,
                DisplayName = Path.GetFileName(candidate.CertificatePath),
                CertificatePath = candidate.CertificatePath,
                ContainerPath = candidate.ContainerPath
            };

            if (!string.IsNullOrWhiteSpace(candidate.SkipReason))
            {
                task.Status = SignatureTaskStatus.Skipped;
                task.Message = candidate.SkipReason;
            }

            tasks.Add(task);
        }

        logger.Info($"Сканирование завершено. Найдено задач: {tasks.Count}.");
        return tasks;
    }

    private static ScanCandidate BuildPfxCandidate(string file, string password, AppLogger logger)
    {
        var candidate = new ScanCandidate
        {
            Kind = SignatureSourceKind.Pfx,
            CertificatePath = file,
            IsInstallable = true
        };

        try
        {
            using var cert = new X509Certificate2(file, password, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.EphemeralKeySet);
            candidate.Subject = cert.Subject;
            candidate.NotAfter = cert.NotAfter;
            candidate.OwnerKey = BuildOwnerKey(cert.Subject);
            logger.Info($"Обнаружен PFX: {Path.GetFileName(file)}; Subject={cert.Subject}; NotAfter={cert.NotAfter:yyyy-MM-dd}");
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось прочитать метаданные PFX '{file}' для отбора актуального сертификата: {ex.Message}");
        }

        return candidate;
    }

    private static ScanCandidate BuildCerCandidate(string file, AppLogger logger)
    {
        var directory = Path.GetDirectoryName(file) ?? string.Empty;
        var baseName = Path.GetFileNameWithoutExtension(file);
        var containerPath = FindContainerCandidate(directory, baseName, logger);

        var candidate = new ScanCandidate
        {
            Kind = SignatureSourceKind.CryptoProContainer,
            CertificatePath = file,
            ContainerPath = containerPath,
            IsInstallable = !string.IsNullOrWhiteSpace(containerPath)
        };

        if (!candidate.IsInstallable)
        {
            candidate.SkipReason = "Пропущено: нет приватного ключа";
        }

        try
        {
            using var cert = new X509Certificate2(file);
            candidate.Subject = cert.Subject;
            candidate.NotAfter = cert.NotAfter;
            candidate.OwnerKey = BuildOwnerKey(cert.Subject);
            logger.Info($"Обнаружен CER: {Path.GetFileName(file)}; Subject={cert.Subject}; NotAfter={cert.NotAfter:yyyy-MM-dd}");
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось прочитать сертификат '{file}': {ex.Message}");
        }

        return candidate;
    }

    private static void ApplyMostActualRule(List<ScanCandidate> candidates, AppLogger logger)
    {
        var now = DateTime.Now;

        foreach (var candidate in candidates.Where(x => x.IsInstallable && x.NotAfter.HasValue && x.NotAfter.Value < now))
        {
            candidate.SkipReason = "Пропущено: Просрочен";
        }

        var grouped = candidates
            .Where(x => x.IsInstallable && string.IsNullOrWhiteSpace(x.SkipReason) && x.NotAfter.HasValue && !string.IsNullOrWhiteSpace(x.OwnerKey))
            .GroupBy(x => x.OwnerKey!, StringComparer.OrdinalIgnoreCase);

        foreach (var group in grouped)
        {
            var selected = group.OrderByDescending(x => x.NotAfter).First();
            logger.Info($"Выбран самый актуальный сертификат: {Path.GetFileName(selected.CertificatePath)}; Subject={selected.Subject}; NotAfter={selected.NotAfter:yyyy-MM-dd}");

            foreach (var other in group.Where(x => !ReferenceEquals(x, selected)))
            {
                other.SkipReason = $"Пропущено: Есть более актуальный до {selected.NotAfter:yyyy-MM-dd}";
            }
        }
    }

    private static IEnumerable<string> ExpandFiles(IEnumerable<string> inputPaths, AppLogger logger)
    {
        foreach (var path in inputPaths)
        {
            if (File.Exists(path))
            {
                yield return Path.GetFullPath(path);
                continue;
            }

            if (Directory.Exists(path))
            {
                foreach (var file in EnumerateFilesSafe(path, logger))
                {
                    yield return file;
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string rootPath, AppLogger logger)
    {
        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(rootPath);

        while (pendingDirectories.Count > 0)
        {
            var currentDirectory = pendingDirectories.Pop();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(currentDirectory);
            }
            catch (UnauthorizedAccessException)
            {
                logger.Warn($"Нет доступа к каталогу '{currentDirectory}', пропускаем.");
                continue;
            }
            catch (DirectoryNotFoundException)
            {
                logger.Warn($"Каталог '{currentDirectory}' не найден во время сканирования, пропускаем.");
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            IEnumerable<string> subDirectories;
            try
            {
                subDirectories = Directory.EnumerateDirectories(currentDirectory);
            }
            catch (UnauthorizedAccessException)
            {
                logger.Warn($"Нет доступа к подкаталогам '{currentDirectory}', пропускаем.");
                continue;
            }
            catch (DirectoryNotFoundException)
            {
                logger.Warn($"Каталог '{currentDirectory}' был удален во время сканирования, пропускаем.");
                continue;
            }

            foreach (var subDirectory in subDirectories)
            {
                pendingDirectories.Push(subDirectory);
            }
        }
    }

    private static string? FindContainerCandidate(string directory, string baseName, AppLogger logger)
    {
        var directFolder = Path.Combine(directory, baseName);
        if (Directory.Exists(directFolder))
        {
            return directFolder;
        }

        try
        {
            var possible = Directory.EnumerateDirectories(directory)
                .FirstOrDefault(d => Path.GetFileName(d).Contains(baseName, StringComparison.OrdinalIgnoreCase));
            return possible;
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось проверить контейнер рядом с '{directory}': {ex.Message}");
            return null;
        }
    }

    private static string BuildOwnerKey(string subject)
    {
        var inn = ExtractValue(subject, "INN");
        if (!string.IsNullOrWhiteSpace(inn)) return $"INN:{inn}";

        var ogrn = ExtractValue(subject, "OGRN");
        if (!string.IsNullOrWhiteSpace(ogrn)) return $"OGRN:{ogrn}";

        var cn = ExtractValue(subject, "CN");
        if (!string.IsNullOrWhiteSpace(cn)) return $"CN:{cn}";

        return $"SUBJECT:{subject}";
    }

    private static string ExtractValue(string source, string key)
    {
        var match = Regex.Match(source, $@"{key}\s*=\s*([^,]+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
    }

    private sealed class ScanCandidate
    {
        public SignatureSourceKind Kind { get; init; }
        public string CertificatePath { get; init; } = string.Empty;
        public string? ContainerPath { get; init; }
        public bool IsInstallable { get; init; }
        public string? Subject { get; set; }
        public DateTime? NotAfter { get; set; }
        public string? OwnerKey { get; set; }
        public string? SkipReason { get; set; }
    }
}
