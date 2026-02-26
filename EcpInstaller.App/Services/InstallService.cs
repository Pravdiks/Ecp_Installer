using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace EcpInstaller.App.Services;

public sealed class InstallService
{
    /// <summary>provtype fallback order: GOST-2012-256, GOST-2001, GOST-2012-512.</summary>
    private static readonly int[] ProvTypes = [80, 75, 81];

    private readonly AppLogger _logger;
    private readonly CryptoProCli _cryptoProCli;

    public InstallService(AppLogger logger, CryptoProCli cryptoProCli)
    {
        _logger = logger;
        _cryptoProCli = cryptoProCli;
    }

    public async Task InstallAsync(SignatureTask task, string password, StoreLocation storeLocation, ContainerLocation containerLocation, string containerFolder)
    {
        task.Status = SignatureTaskStatus.Running;
        task.Message = "Установка...";

        try
        {
            switch (task.Kind)
            {
                case SignatureSourceKind.Pfx:
                    InstallPfx(task, password, storeLocation);
                    break;
                case SignatureSourceKind.CryptoProContainer:
                    await InstallCryptoProAsync(task, password, storeLocation, containerLocation, containerFolder);
                    break;
            }

            task.Status = SignatureTaskStatus.Success;
            task.Message = task.HasPrivateKey == false
                ? "Установлено (ключ не привязан!)"
                : "Установлено";
        }
        catch (OperationCanceledException ex)
        {
            task.Status = SignatureTaskStatus.Skipped;
            task.Message = ex.Message;
            _logger.Warn($"Пропуск задачи '{task.DisplayName}': {ex.Message}");
        }
        catch (Exception ex)
        {
            task.Status = SignatureTaskStatus.Error;
            task.Message = $"Ошибка: {ex.Message}";
            _logger.Error($"Ошибка установки '{task.DisplayName}': {ex}");
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  PFX
    // ──────────────────────────────────────────────────────────────

    private void InstallPfx(SignatureTask task, string password, StoreLocation storeLocation)
    {
        EnsureAccess(storeLocation);
        var keyStorageFlags = X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable;
        if (storeLocation == StoreLocation.LocalMachine)
            keyStorageFlags |= X509KeyStorageFlags.MachineKeySet;

        var cert = new X509Certificate2(task.CertificatePath, password, keyStorageFlags);
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        _logger.Info($@"PFX установлен: {task.CertificatePath} в {storeLocation}\My");
        RemoveOldCertificatesExcept(store, cert);
        task.HasPrivateKey = cert.HasPrivateKey;
    }

    // ──────────────────────────────────────────────────────────────
    //  CryptoPro CER + container
    // ──────────────────────────────────────────────────────────────

    private async Task InstallCryptoProAsync(
        SignatureTask task, string password, StoreLocation storeLocation,
        ContainerLocation containerLocation, string containerFolder)
    {
        EnsureAccess(storeLocation);

        var certMgr = _cryptoProCli.ResolveCertMgrPath();
        if (certMgr is null)
            throw new InvalidOperationException("CryptoPro CSP не найден (certmgr.exe отсутствует). Установите CSP или используйте PFX.");

        if (string.IsNullOrWhiteSpace(task.ContainerPath) || !Directory.Exists(task.ContainerPath))
            throw new InvalidOperationException("Для CER не найден контейнер закрытого ключа рядом с сертификатом.");

        var cspVer = _cryptoProCli.ResolveCspVersion();
        _logger.Info($"CryptoPro CSP версия: {(cspVer > 0 ? cspVer.ToString() : "не определена")}");

        var locationArg     = storeLocation == StoreLocation.CurrentUser ? "uMy" : "mMy";
        var sourceContainer = task.ContainerPath!;

        // ═══════════════════════════════════════════════════════════
        // ШАГ 1: ВСЕГДА копируем контейнер в РЕЕСТР КриптоПро.
        // Только \\.\REGISTRY\... принимает -pin без GUI диалога.
        // HDIMAGE и FAT12 считыватели полностью игнорируют -pin.
        // ═══════════════════════════════════════════════════════════
        var contUncPath = await CopyContainerToRegistryAsync(sourceContainer);

        // ═══════════════════════════════════════════════════════════
        // ШАГ 2: Режим "Диск" — дополнительно копируем контейнер
        // в указанную папку (для хранения). Не критично для установки
        // — certmgr всё равно использует реестровую копию.
        // ═══════════════════════════════════════════════════════════
        if (containerLocation == ContainerLocation.Disk)
        {
            try
            {
                var actualFolder = EnsureContainerFolder(containerFolder);
                var diskDest = Path.Combine(actualFolder,
                    Path.GetFileName(sourceContainer.TrimEnd(
                        Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));

                var srcFull = Path.GetFullPath(sourceContainer)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                var dstFull = Path.GetFullPath(diskDest)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                if (!string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
                {
                    Directory.CreateDirectory(diskDest);
                    await Task.Run(() => CopyContainerFiles(sourceContainer, diskDest));
                    _logger.Info($"Контейнер скопирован на диск: {diskDest}");
                }
                else
                {
                    _logger.Info($"Контейнер уже в целевой папке: {srcFull}");
                }
            }
            catch (Exception ex)
            {
                _logger.Warn($"Не удалось скопировать контейнер на диск: {ex.Message}. Установка через реестр продолжится.");
            }
        }

        // ═══════════════════════════════════════════════════════════
        // ШАГ 3: Пауза — КриптоПро иногда не успевает "увидеть"
        // только что скопированный реестровый контейнер.
        // ═══════════════════════════════════════════════════════════
        await Task.Delay(1000);

        // ═══════════════════════════════════════════════════════════
        // ШАГ 4: certmgr с реестровым UNC-путём. -pin гарантированно
        // принимается без GUI диалога для \\.\REGISTRY\...
        // ═══════════════════════════════════════════════════════════
        int lastExitCode = -1;
        string? lastOutput = null;

        foreach (var provType in ProvTypes)
        {
            (lastExitCode, lastOutput) = await RunCertMgrInstallAsync(
                certMgr, task.CertificatePath, contUncPath, password, locationArg, provType);
            if (lastExitCode == 0) break;
            _logger.Warn($"certmgr -provtype {provType} завершился с кодом {lastExitCode}.");
        }

        if (lastExitCode != 0)
            throw new InvalidOperationException(
                $"certmgr завершился с кодом {lastExitCode}.\n{lastOutput}");

        _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}");
        _logger.Info($"UNC контейнера: {contUncPath}");

        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, new X509Certificate2(task.CertificatePath));

        // ═══════════════════════════════════════════════════════════
        // ШАГ 5: Проверка привязки закрытого ключа + repairstore
        // ═══════════════════════════════════════════════════════════
        await VerifyAndRepairPrivateKeyAsync(task, storeLocation);
    }

    // ──────────────────────────────────────────────────────────────
    //  Registry container placement
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Copies the container folder to <c>%APPDATA%\Crypto Pro\Keys\{name}\</c>
    /// where <c>{name}</c> is the raw folder name with its numeric extension stripped
    /// (e.g. <c>rwowmbby.001</c> → <c>rwowmbby</c>).
    /// Recreates the destination to ensure a clean copy.
    /// Returns <c>\\.\REGISTRY\{name}</c>.
    /// </summary>
    private async Task<string> CopyContainerToRegistryAsync(string sourceContainerPath)
    {
        var keysRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Crypto Pro", "Keys");
        Directory.CreateDirectory(keysRoot);

        var rawName = Path.GetFileName(
            sourceContainerPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        // Strip .NNN numeric extension (e.g. "rwowmbby.001" → "rwowmbby").
        // Only strip when the extension consists entirely of digits.
        var ext     = Path.GetExtension(rawName);
        var regName = ext.Length > 1 && ext[1..].All(char.IsDigit)
            ? Path.GetFileNameWithoutExtension(rawName)
            : rawName;

        var destFolder = Path.Combine(keysRoot, regName);

        // Recreate destination to ensure a clean copy — avoids stale files from a previous run.
        if (Directory.Exists(destFolder))
            Directory.Delete(destFolder, recursive: true);
        Directory.CreateDirectory(destFolder);

        await Task.Run(() => CopyContainerFiles(sourceContainerPath, destFolder));

        var uncPath = $@"\\.\REGISTRY\{regName}";
        _logger.Info($"Контейнер скопирован в реестр: {destFolder}. UNC: {uncPath}");
        return uncPath;
    }

    // ──────────────────────────────────────────────────────────────
    //  Container folder helpers (disk mode)
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates <paramref name="requestedFolder"/> and returns it.
    /// Falls back to <c>%APPDATA%\EcpInstaller\Containers</c> if the drive
    /// is unavailable or the directory cannot be created.
    /// </summary>
    private string EnsureContainerFolder(string requestedFolder)
    {
        try
        {
            var root = Path.GetPathRoot(requestedFolder);
            if (!string.IsNullOrEmpty(root) && !Directory.Exists(root))
            {
                _logger.Warn($"Диск {root} недоступен.");
                return FallbackContainerFolder();
            }
            Directory.CreateDirectory(requestedFolder);
            return requestedFolder;
        }
        catch (Exception ex)
        {
            _logger.Warn($"Ошибка создания папки '{requestedFolder}': {ex.Message}");
            return FallbackContainerFolder();
        }
    }

    private string FallbackContainerFolder()
    {
        var fallback = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "EcpInstaller", "Containers");
        Directory.CreateDirectory(fallback);
        _logger.Warn($"Используется fallback-папка для контейнеров: {fallback}");
        return fallback;
    }

    // ──────────────────────────────────────────────────────────────
    //  Private key verification and repair
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Checks whether the installed certificate has a linked private key.
    /// If not, attempts <c>certutil -repairstore</c> once and re-checks.
    /// Always sets <see cref="SignatureTask.HasPrivateKey"/>.
    /// </summary>
    private async Task VerifyAndRepairPrivateKeyAsync(SignatureTask task, StoreLocation storeLocation)
    {
        var thumbprint = GetCertThumbprint(task.CertificatePath);
        _logger.Info($"Thumbprint: {thumbprint}");

        await Task.Delay(500); // brief pause for CryptoPro to finalize the key mapping

        var hasKey = CheckPrivateKeyLinked(thumbprint, storeLocation);
        _logger.Info($"HasPrivateKey после установки: {hasKey}");

        if (!hasKey)
        {
            _logger.Info("Попытка привязки ключа через certutil -repairstore...");
            var userFlag = storeLocation == StoreLocation.CurrentUser ? "-user " : string.Empty;
            var (repairCode, repairOut) = await RunSystemCommandAsync(
                "certutil.exe", $"-repairstore {userFlag}My \"{thumbprint}\"");
            _logger.Info($"certutil -repairstore код {repairCode}. Вывод:\n{repairOut}");

            await Task.Delay(300);
            hasKey = CheckPrivateKeyLinked(thumbprint, storeLocation);
            _logger.Info($"HasPrivateKey после repairstore: {hasKey}");
        }

        if (!hasKey)
        {
            _logger.Warn($"Ключ не привязан для '{task.DisplayName}'. " +
                "Сертификат установлен, но подпись может не работать.");
        }

        task.HasPrivateKey = hasKey;
    }

    /// <summary>Returns the thumbprint (uppercase, no spaces) read from a certificate file.</summary>
    private static string GetCertThumbprint(string cerPath)
    {
        using var cert = new X509Certificate2(cerPath);
        return cert.Thumbprint;
    }

    /// <summary>
    /// Opens the store and returns <c>true</c> if the certificate with the given thumbprint
    /// reports <see cref="X509Certificate2.HasPrivateKey"/>.
    /// </summary>
    private static bool CheckPrivateKeyLinked(string thumbprint, StoreLocation storeLocation)
    {
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadOnly);
        var cert = store.Certificates
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));
        return cert?.HasPrivateKey ?? false;
    }

    // ──────────────────────────────────────────────────────────────
    //  certmgr invocation
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs <c>certmgr -inst … -cont "{contUncPath}"</c> and returns the exit code + output.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrInstallAsync(
        string certMgr, string cerPath, string contUncPath,
        string password, string locationArg, int provType)
    {
        var pinArg    = !string.IsNullOrEmpty(password) ? $@" -pin ""{password}""" : string.Empty;
        var pinForLog = !string.IsNullOrEmpty(password) ? @" -pin ""***"""         : string.Empty;

        var args   = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pinArg} -silent";
        var forLog = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pinForLog} -silent";
        _logger.Info($"Запуск: {certMgr} {forLog}");

        var result = await _cryptoProCli.RunAsync(certMgr, args);
        _logger.Info($"certmgr код {result.ExitCode}. Вывод:\n{result.Output}");
        return result;
    }

    // ──────────────────────────────────────────────────────────────
    //  File and process helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>Copies all files from <paramref name="sourceDir"/> into <paramref name="destDir"/> (flat, no recursion).</summary>
    private static void CopyContainerFiles(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir))
            File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)), overwrite: true);
    }

    /// <summary>Runs an arbitrary system executable (e.g. certutil.exe) and captures stdout + stderr.</summary>
    private static async Task<(int ExitCode, string Output)> RunSystemCommandAsync(string exe, string arguments)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute  = false,
            CreateNoWindow   = true
        };
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Не удалось запустить: {exe}");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode,
            string.Join(Environment.NewLine,
                new[] { stdout, stderr }.Where(x => !string.IsNullOrWhiteSpace(x))));
    }

    // ──────────────────────────────────────────────────────────────
    //  Old-certificate cleanup
    // ──────────────────────────────────────────────────────────────

    private void RemoveOldCertificatesExcept(X509Store store, X509Certificate2 incoming)
    {
        var oldOnes = store.Certificates.Cast<X509Certificate2>()
            .Where(existing => !string.Equals(existing.Thumbprint, incoming.Thumbprint, StringComparison.OrdinalIgnoreCase))
            .Where(existing => CertificateIdentityMatcher.IsSameOwner(existing, incoming))
            .ToList();

        _logger.Info($"Найдено старых сертификатов на удаление: {oldOnes.Count}; Subject={incoming.Subject}");

        foreach (var old in oldOnes)
        {
            store.Remove(old);
            _logger.Info($"Удален старый сертификат: Subject={old.Subject}; Serial={old.SerialNumber}. Причина: найдено совпадение владельца.");
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Access control
    // ──────────────────────────────────────────────────────────────

    private static void EnsureAccess(StoreLocation storeLocation)
    {
        if (storeLocation == StoreLocation.LocalMachine && !OperatingSystem.IsWindows())
            throw new InvalidOperationException("LocalMachine поддерживается только на Windows.");

        if (storeLocation == StoreLocation.LocalMachine && !WindowsPrincipalHelper.IsAdministrator())
            throw new OperationCanceledException("Для LocalMachine нужны права администратора. Выберите CurrentUser для установки без админа.");
    }
}
