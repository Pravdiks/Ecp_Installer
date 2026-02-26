using EcpInstaller.App.Models;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EcpInstaller.App.Services;

public sealed class ScanService
{
    private static readonly HashSet<string> PfxExtensions = [".pfx", ".p12"];
    private static readonly HashSet<string> CertExtensions = [".cer", ".crt"];
    private static readonly Regex ContainerDirPattern = new(@"\.\d{3}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public IReadOnlyCollection<SignatureTask> Scan(IEnumerable<string> inputPaths, AppLogger logger, bool onlyMostActual, string pfxPassword)
    {
        var files = ExpandFiles(inputPaths, logger).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var directories = ExpandDirectories(inputPaths, logger).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var candidates = new List<ScanCandidate>();

        foreach (var file in files)
        {
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (PfxExtensions.Contains(ext))
                candidates.Add(BuildPfxCandidate(file, pfxPassword, logger));
        }

        var cerFiles = files
            .Where(f => CertExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var containerFolders = directories
            .Where(IsContainerFolder)
            .ToList();

        var usedCers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var container in containerFolders)
        {
            var cer = FindNearestCertificate(container, cerFiles);
            if (cer is null)
            {
                logger.Warn($"Контейнер найден, но рядом нет CER: {container}");
                continue;
            }

            usedCers.Add(cer);
            candidates.Add(BuildCerCandidate(cer, container, logger));
        }

        foreach (var cer in cerFiles.Where(c => !usedCers.Contains(c)))
            candidates.Add(BuildCerWithoutContainerCandidate(cer, logger));

        if (onlyMostActual)
            ApplyMostActualRule(candidates, logger);

        var uniqueMap = new Dictionary<string, SignatureTask>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            var containerPart = candidate.ContainerPath ?? string.Empty;
            var key = $"{candidate.CertificatePath}|{containerPart}";
            if (uniqueMap.ContainsKey(key))
                continue;

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

            uniqueMap[key] = task;
        }

        var tasks = uniqueMap.Values.ToList();

        logger.Info($"Сканирование завершено. Найдено задач: {tasks.Count}.");
        return tasks;
    }

    private static bool IsContainerFolder(string path)
    {
        var name = Path.GetFileName(path);
        if (!ContainerDirPattern.IsMatch(name))
            return false;

        var keyCount = Directory.EnumerateFiles(path, "*.key", SearchOption.TopDirectoryOnly).Take(3).Count();
        return keyCount >= 2;
    }

    private static string? FindNearestCertificate(string containerPath, IReadOnlyCollection<string> certs)
    {
        var folder = Path.GetDirectoryName(containerPath);
        if (folder is null)
            return null;

        var sameDir = certs.FirstOrDefault(c => string.Equals(Path.GetDirectoryName(c), folder, StringComparison.OrdinalIgnoreCase));
        if (sameDir is not null)
            return sameDir;

        var parent = Directory.GetParent(folder)?.FullName;
        if (parent is null)
            return null;

        return certs.FirstOrDefault(c => string.Equals(Path.GetDirectoryName(c), parent, StringComparison.OrdinalIgnoreCase));
    }

    private static ScanCandidate BuildPfxCandidate(string file, string password, AppLogger logger)
    {
        var candidate = new ScanCandidate { Kind = SignatureSourceKind.Pfx, CertificatePath = file, IsInstallable = true };
        try
        {
            using var cert = new X509Certificate2(file, password, X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.EphemeralKeySet);
            candidate.Subject = cert.Subject;
            candidate.NotAfter = cert.NotAfter;
            candidate.OwnerKey = BuildOwnerKey(cert.Subject);
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось прочитать метаданные PFX '{file}': {ex.Message}");
        }

        return candidate;
    }

    private static ScanCandidate BuildCerCandidate(string file, string containerPath, AppLogger logger)
    {
        var candidate = new ScanCandidate
        {
            Kind = SignatureSourceKind.CryptoProContainer,
            CertificatePath = file,
            ContainerPath = containerPath,
            IsInstallable = true
        };

        TryFillCertificateMeta(candidate, logger);
        logger.Info($"Пара для установки: CER={file} CONTAINER={containerPath}");
        return candidate;
    }

    private static ScanCandidate BuildCerWithoutContainerCandidate(string file, AppLogger logger)
    {
        var candidate = new ScanCandidate
        {
            Kind = SignatureSourceKind.CryptoProContainer,
            CertificatePath = file,
            IsInstallable = false,
            SkipReason = "Невозможно установить закрытый ключ: CER не содержит private key"
        };

        TryFillCertificateMeta(candidate, logger);
        logger.Warn($"CER без контейнера: {file}");
        return candidate;
    }

    private static void TryFillCertificateMeta(ScanCandidate candidate, AppLogger logger)
    {
        try
        {
            using var cert = new X509Certificate2(candidate.CertificatePath);
            candidate.Subject = cert.Subject;
            candidate.NotAfter = cert.NotAfter;
            candidate.OwnerKey = BuildOwnerKey(cert.Subject);
        }
        catch (Exception ex)
        {
            logger.Warn($"Не удалось прочитать сертификат '{candidate.CertificatePath}': {ex.Message}");
        }
    }

    private static void ApplyMostActualRule(List<ScanCandidate> candidates, AppLogger logger)
    {
        var now = DateTime.Now;

        foreach (var candidate in candidates.Where(x => x.IsInstallable && x.NotAfter.HasValue && x.NotAfter.Value < now))
            candidate.SkipReason = "Пропущено: Просрочен";

        var grouped = candidates
            .Where(x => x.IsInstallable && string.IsNullOrWhiteSpace(x.SkipReason) && x.NotAfter.HasValue && !string.IsNullOrWhiteSpace(x.OwnerKey))
            .GroupBy(x => x.OwnerKey!, StringComparer.OrdinalIgnoreCase);

        foreach (var group in grouped)
        {
            var selected = group.OrderByDescending(x => x.NotAfter).First();
            foreach (var other in group.Where(x => !ReferenceEquals(x, selected)))
                other.SkipReason = $"Пропущено: есть более актуальный до {selected.NotAfter:yyyy-MM-dd}";

            logger.Info($"Выбран наиболее актуальный сертификат: {Path.GetFileName(selected.CertificatePath)}");
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
                    yield return file;
            }
        }
    }

    private static IEnumerable<string> ExpandDirectories(IEnumerable<string> inputPaths, AppLogger logger)
    {
        foreach (var path in inputPaths)
        {
            if (Directory.Exists(path))
            {
                foreach (var dir in EnumerateDirectoriesSafe(path, logger))
                    yield return dir;
            }
            else if (File.Exists(path))
            {
                var parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(parent))
                    yield return parent;
            }
        }
    }

    private static IEnumerable<string> EnumerateDirectoriesSafe(string rootPath, AppLogger logger)
    {
        var pending = new Stack<string>();
        pending.Push(rootPath);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            yield return current;

            IEnumerable<string> subDirs;
            try { subDirs = Directory.EnumerateDirectories(current); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or DirectoryNotFoundException)
            {
                logger.Warn($"Каталог '{current}' недоступен: {ex.Message}");
                continue;
            }

            foreach (var sub in subDirs)
                pending.Push(sub);
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string rootPath, AppLogger logger)
    {
        foreach (var dir in EnumerateDirectoriesSafe(rootPath, logger))
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or DirectoryNotFoundException)
            {
                logger.Warn($"Файлы каталога '{dir}' недоступны: {ex.Message}");
                continue;
            }

            foreach (var file in files)
                yield return file;
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
