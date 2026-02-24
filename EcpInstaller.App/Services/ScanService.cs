using EcpInstaller.App.Models;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EcpInstaller.App.Services;

public sealed class ScanService
{
    private static readonly HashSet<string> PfxExtensions = [".pfx", ".p12"];
    private static readonly HashSet<string> CertExtensions = [".cer", ".crt"];

    // CryptoPro container directory has a numeric 3-digit extension: .000, .001, .002 ...
    private static readonly Regex ContainerDirPattern = new(@"^\.\d{3}$", RegexOptions.Compiled);

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

        logger.Info($"Обрабатывается CER: {file}");
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
            candidate.SkipReason = "Пропущено: нет ключа";
            logger.Warn($"CER без контейнера — будет пропущен: {file}");
        }
        else
        {
            logger.Info($"CER связан с контейнером: {file}  →  {containerPath}");
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
                // Skip CryptoPro container folders (*.NNN) — they hold key files, not certificates.
                // Scanning into them wastes time and never yields .cer files.
                var dirExt = Path.GetExtension(Path.GetFileName(subDirectory));
                if (ContainerDirPattern.IsMatch(dirExt))
                {
                    continue;
                }
                pendingDirectories.Push(subDirectory);
            }
        }
    }

    private static string? FindContainerCandidate(string directory, string baseName, AppLogger logger)
    {
        // CryptoPro container is a directory with a 3-digit numeric extension (.000, .001, ...)
        // and must contain primary.key inside. It always lives in the same directory as the .cer file.
        try
        {
            var containers = Directory.EnumerateDirectories(directory)
                .Where(d => ContainerDirPattern.IsMatch(Path.GetExtension(Path.GetFileName(d)))
                            && File.Exists(Path.Combine(d, "primary.key")))
                .ToList();

            if (containers.Count == 0)
            {
                logger.Warn($"Контейнер закрытого ключа не найден в '{directory}' " +
                            $"(нет папок *.NNN с файлом primary.key).");
                return null;
            }

            if (containers.Count == 1)
            {
                logger.Info($"Контейнер найден: {containers[0]}");
                return containers[0];
            }

            // Multiple containers in same directory — prefer the one whose stem matches
            // the .cer filename, otherwise take the one with the lowest index (.000 first).
            var preferred = containers.FirstOrDefault(d =>
                Path.GetFileNameWithoutExtension(d)
                    .Contains(baseName, StringComparison.OrdinalIgnoreCase));
            var selected = preferred
                           ?? containers.OrderBy(d => Path.GetExtension(d), StringComparer.Ordinal).First();
            logger.Info($"Найдено контейнеров: {containers.Count}, выбран: {selected}");
            return selected;
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось проверить контейнеры рядом с '{directory}': {ex.Message}");
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
