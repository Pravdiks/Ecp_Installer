using EcpInstaller.App.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EcpInstaller.App.Services;

public sealed class InstallerService
{
    private readonly AppLogger _logger;
    private readonly CryptoProCliService _cli;

    public InstallerService(AppLogger logger, CryptoProCliService cli)
    {
        _logger = logger;
        _cli = cli;
    }

    public async Task InstallContainerAndBindCertAsync(
        string containerFolder,
        string cerPath,
        ContainerLocation containerLocation,
        string requestedContainerFolder,
        string? password = null,
        CancellationToken ct = default)
    {
        if (!Directory.Exists(containerFolder))
            throw new DirectoryNotFoundException($"Папка контейнера не найдена: {containerFolder}");
        if (!File.Exists(cerPath))
            throw new FileNotFoundException("Файл сертификата не найден", cerPath);

        var before = await _cli.EnumerateContainersFqcnAsync(ct);

        string sourceName = Path.GetFileName(containerFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        string targetPath;
        string? substDrive = null;

        try
        {
            if (containerLocation == ContainerLocation.Registry)
            {
                var keysRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Crypto Pro", "Keys");
                Directory.CreateDirectory(keysRoot);
                var targetName = EnsureUniqueFolderName(keysRoot, sourceName);
                targetPath = Path.Combine(keysRoot, targetName);
            }
            else
            {
                var diskBase = ResolveDiskBasePath(requestedContainerFolder);
                if (!IsRootPath(diskBase))
                {
                    substDrive = FindFreeDriveLetter();
                    MountSubst(substDrive, diskBase, password);
                    diskBase = $"{substDrive}:\\";
                }

                var targetName = EnsureUniqueFolderName(diskBase, sourceName);
                targetPath = Path.Combine(diskBase, targetName);
            }

            CopyContainer(containerFolder, targetPath);
            _logger.Info($"Контейнер скопирован: {containerFolder} -> {targetPath}");

            await Task.Delay(600, ct);

            var after = await _cli.EnumerateContainersFqcnAsync(ct);
            var resolved = ResolveCanonicalContainerAfterCopy(before, after, sourceName, Path.GetFileName(targetPath));

            var fqcnForBind = resolved.Unique ?? resolved.Short;
            if (string.IsNullOrWhiteSpace(fqcnForBind))
            {
                _logger.Error($"Не найден канонический контейнер после копирования: {Path.GetFileName(targetPath)}\n" +
                    $"before.short: {string.Join(", ", before.ContainersShort)}\n" +
                    $"before.unique: {string.Join(", ", before.ContainersUnique)}\n" +
                    $"after.short: {string.Join(", ", after.ContainersShort)}\n" +
                    $"after.unique: {string.Join(", ", after.ContainersUnique)}\n" +
                    $"new.short: {string.Join(", ", resolved.NewShort)}\n" +
                    $"new.unique: {string.Join(", ", resolved.NewUnique)}\n" +
                    $"csptest args before={before.UsedArgs}, after={after.UsedArgs}");
                throw new InvalidOperationException($"Не найден канонический контейнер после копирования: {Path.GetFileName(targetPath)}. Проверьте csptest -enum_cont output.");
            }

            var certmgr = _cli.FindCertmgrPath();
            var instToCont = await _cli.ResolveInstallToContArgAsync(ct);

            var pinArg = string.IsNullOrWhiteSpace(password) ? string.Empty : $" -pin \"{password}\"";
            var args = $"-inst -store uMy -file \"{cerPath}\" -cont \"{fqcnForBind}\" {instToCont} -silent{pinArg}";

            var result = await _cli.RunProcessAsync(certmgr, args, secretsToMask: password is null ? null : [password], cancellationToken: ct);
            _logger.Info($"certmgr install result: exit={result.ExitCode}; output:\n{result.Output}");
            if (result.ExitCode != 0)
                throw new InvalidOperationException($"certmgr -inst завершился с кодом {result.ExitCode}.\n{result.Output}");

            await VerifyInstallAsync(cerPath, password, ct);
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(substDrive))
            {
                try { UnmountSubst(substDrive, password); }
                catch (Exception ex) { _logger.Warn($"Не удалось снять subst {substDrive}: {ex.Message}"); }
            }
        }
    }

    public async Task VerifyInstallAsync(string cerPath, string? password, CancellationToken ct)
    {
        var certmgr = _cli.FindCertmgrPath();
        var listResult = await _cli.RunProcessAsync(certmgr, "-list -store uMy", secretsToMask: password is null ? null : [password], cancellationToken: ct);
        if (listResult.ExitCode != 0)
            _logger.Warn($"certmgr -list -store uMy вернул код {listResult.ExitCode}: {listResult.Output}");

        using var cert = new X509Certificate2(cerPath);
        var thumbprint = cert.Thumbprint;

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var found = store.Certificates.Cast<X509Certificate2>()
            .FirstOrDefault(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));

        if (found is null)
            throw new InvalidOperationException("Сертификат не найден в CurrentUser\\My после установки.");

        if (!found.HasPrivateKey)
            throw new InvalidOperationException("Сертификат установлен, но закрытый ключ не привязан (HasPrivateKey=False).");
    }

    private string ResolveDiskBasePath(string requestedContainerFolder)
    {
        if (string.IsNullOrWhiteSpace(requestedContainerFolder))
        {
            var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Crypto Pro");
            Directory.CreateDirectory(fallback);
            return fallback;
        }

        Directory.CreateDirectory(requestedContainerFolder);
        return requestedContainerFolder;
    }

    private static bool IsRootPath(string path)
    {
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetPathRoot(full)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return !string.IsNullOrWhiteSpace(root) && string.Equals(full, root, StringComparison.OrdinalIgnoreCase);
    }

    private string FindFreeDriveLetter()
    {
        var used = DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])).ToHashSet();
        for (char letter = 'Z'; letter >= 'R'; letter--)
        {
            if (!used.Contains(letter))
                return letter.ToString();
        }

        throw new InvalidOperationException("Не удалось найти свободную букву диска для SUBST.");
    }

    private void MountSubst(string driveLetter, string targetPath, string? password)
    {
        var args = $"/c subst {driveLetter}: \"{targetPath}\"";
        var result = _cli.RunProcessAsync("cmd.exe", args, secretsToMask: password is null ? null : [password]).GetAwaiter().GetResult();
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Не удалось создать subst {driveLetter}: для '{targetPath}'. {result.Output}");

        _logger.Info($"Создан SUBST: {driveLetter}: -> {targetPath}");
    }

    private void UnmountSubst(string driveLetter, string? password)
    {
        var args = $"/c subst {driveLetter}: /d";
        var result = _cli.RunProcessAsync("cmd.exe", args, secretsToMask: password is null ? null : [password]).GetAwaiter().GetResult();
        if (result.ExitCode == 0)
            _logger.Info($"Удален SUBST: {driveLetter}:");
        else
            _logger.Warn($"SUBST /d вернул код {result.ExitCode} для {driveLetter}: {result.Output}");
    }

    private static CanonicalContainerResolveResult ResolveCanonicalContainerAfterCopy(
        ContainerEnumerationResult before,
        ContainerEnumerationResult after,
        string sourceFolderName,
        string actualTargetFolderName)
    {
        var newShort = after.ContainersShort.Except(before.ContainersShort, StringComparer.OrdinalIgnoreCase).ToArray();
        var newUnique = after.ContainersUnique.Except(before.ContainersUnique, StringComparer.OrdinalIgnoreCase).ToArray();

        string? selectedShort = PickCandidate(newShort, sourceFolderName, actualTargetFolderName)
            ?? PickCandidate(after.ContainersShort, sourceFolderName, actualTargetFolderName);

        string? selectedUnique = PickCandidate(newUnique, sourceFolderName, actualTargetFolderName)
            ?? PickCandidate(after.ContainersUnique, sourceFolderName, actualTargetFolderName);

        if (string.IsNullOrWhiteSpace(selectedUnique) && !string.IsNullOrWhiteSpace(selectedShort))
        {
            selectedUnique = after.ContainersUnique.FirstOrDefault(u =>
                u.Contains(actualTargetFolderName, StringComparison.OrdinalIgnoreCase)
                || u.Contains(sourceFolderName, StringComparison.OrdinalIgnoreCase)
                || u.Contains(ExtractStem(actualTargetFolderName), StringComparison.OrdinalIgnoreCase));
        }

        return new CanonicalContainerResolveResult(selectedShort, selectedUnique, newShort, newUnique);
    }

    private static string? PickCandidate(IEnumerable<string> items, string sourceFolderName, string actualTargetFolderName)
    {
        var list = items.ToList();
        if (list.Count == 1)
            return list[0];

        var stemSource = ExtractStem(sourceFolderName);
        var stemTarget = ExtractStem(actualTargetFolderName);

        return list.FirstOrDefault(x =>
            x.Contains(actualTargetFolderName, StringComparison.OrdinalIgnoreCase)
            || x.Contains(sourceFolderName, StringComparison.OrdinalIgnoreCase)
            || x.Contains(stemTarget, StringComparison.OrdinalIgnoreCase)
            || x.Contains(stemSource, StringComparison.OrdinalIgnoreCase));
    }

    private static string ExtractStem(string folderName)
    {
        var ext = Path.GetExtension(folderName);
        return !string.IsNullOrWhiteSpace(ext) && Regex.IsMatch(ext, @"^\.\d{3}$")
            ? Path.GetFileNameWithoutExtension(folderName)
            : folderName;
    }

    private static void CopyContainer(string sourceFolder, string destinationFolder)
    {
        if (Directory.Exists(destinationFolder))
            Directory.Delete(destinationFolder, true);

        Directory.CreateDirectory(destinationFolder);
        foreach (var file in Directory.GetFiles(sourceFolder))
            File.Copy(file, Path.Combine(destinationFolder, Path.GetFileName(file)), overwrite: true);
    }

    private static string EnsureUniqueFolderName(string root, string baseName)
    {
        var ext = Path.GetExtension(baseName);
        var stem = Path.GetFileNameWithoutExtension(baseName);
        var hasContainerExt = Regex.IsMatch(ext ?? string.Empty, @"^\.\d{3}$", RegexOptions.IgnoreCase);

        var candidate = baseName;
        var index = 1;
        while (Directory.Exists(Path.Combine(root, candidate)))
        {
            candidate = hasContainerExt
                ? $"{stem}_{index++}{ext}"
                : $"{baseName}_{index++}";
        }

        return candidate;
    }

    private readonly record struct CanonicalContainerResolveResult(
        string? Short,
        string? Unique,
        string[] NewShort,
        string[] NewUnique);
}
