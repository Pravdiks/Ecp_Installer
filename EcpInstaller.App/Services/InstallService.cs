using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

        var certMgrDir  = Path.GetDirectoryName(certMgr)!;
        var locationArg = storeLocation == StoreLocation.CurrentUser ? "uMy" : "mMy";
        var sourceContainer = task.ContainerPath!;
        var folderName = Path.GetFileName(
            sourceContainer.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        // Auto-switch disk mode to registry when the source container lives on a removable
        // drive (USB / FAT12).  certmgr ignores -pin for FAT12 readers and shows a PIN dialog
        // instead; the registry approach uses -cont and -pin which are always honoured.
        if (containerLocation == ContainerLocation.Disk && IsOnRemovableDrive(sourceContainer))
        {
            _logger.Warn($"Контейнер на съёмном носителе ({Path.GetPathRoot(sourceContainer)}). " +
                "Автопереключение на режим Реестр для подавления диалога пароля КриптоПро.");
            containerLocation = ContainerLocation.Registry;
        }

        int lastExitCode = -1;
        string? lastOutput = null;

        if (containerLocation == ContainerLocation.Disk)
        {
            // ── Disk mode: no HDIMAGE registration, no admin rights needed.
            // Copy container to destination folder; place .cer next to it; run certmgr without -cont.
            _logger.Info("Режим Диск: копирование в папку назначения + certmgr без -cont.");

            foreach (var provType in ProvTypes)
            {
                (lastExitCode, lastOutput) = await RunCertMgrDiskModeAsync(
                    certMgr, task.CertificatePath, sourceContainer, folderName,
                    containerFolder, password, locationArg, provType);
                if (lastExitCode == 0) break;
                _logger.Warn($"Диск, certmgr -provtype {provType} завершился с кодом {lastExitCode}.");
            }

            if (lastExitCode != 0)
                throw new InvalidOperationException(
                    $"certmgr (режим Диск) завершился с кодом {lastExitCode}.\n{lastOutput}");
        }
        else
        {
            // ── Registry mode ───────────────────────────────────────────────────────────────
            // Strategy 1: read logical name from name.key, copy to %APPDATA%\Crypto Pro\Keys\,
            //             run certmgr with -cont "\\.\REGISTRY\{logicalName}".
            // Strategy 2 (fallback): temp folder, no -cont.

            _logger.Info("Стратегия 1: установка с -cont (имя из name.key).");
            var strategy1Ok = false;

            try
            {
                var contUncPath = await PlaceContainerToRegistryAsync(sourceContainer, folderName);

                // Pre-cache the container password via csptest so certmgr never shows a PIN dialog.
                await CacheContainerPasswordAsync(certMgrDir, contUncPath, password);

                foreach (var provType in ProvTypes)
                {
                    (lastExitCode, lastOutput) = await RunCertMgrInstallAsync(
                        certMgr, task.CertificatePath, contUncPath, password, locationArg, provType);
                    if (lastExitCode == 0) break;
                    _logger.Warn($"Стратегия 1, certmgr -provtype {provType} завершился с кодом {lastExitCode}.");
                }
                strategy1Ok = lastExitCode == 0;
                if (strategy1Ok)
                    _logger.Info($"Стратегия 1 успешна. UNC: {contUncPath}");
                else
                    _logger.Warn($"Стратегия 1 не удалась (код {lastExitCode}). Переход к стратегии 2.");
            }
            catch (Exception ex)
            {
                _logger.Warn($"Стратегия 1 исключение: {ex.Message}. Переход к стратегии 2.");
            }

            if (!strategy1Ok)
            {
                _logger.Info("Стратегия 2: установка без -cont (temp-папка, авто-обнаружение).");
                foreach (var provType in ProvTypes)
                {
                    (lastExitCode, lastOutput) = await RunCertMgrWithTempFolderAsync(
                        certMgr, task.CertificatePath, sourceContainer, folderName,
                        password, locationArg, provType);
                    if (lastExitCode == 0) break;
                    _logger.Warn($"Стратегия 2, certmgr -provtype {provType} завершился с кодом {lastExitCode}.");
                }

                if (lastExitCode != 0)
                    throw new InvalidOperationException(
                        $"Обе стратегии установки не удались. Последний код: {lastExitCode}.\n{lastOutput}");

                _logger.Info("Стратегия 2 успешна (temp-папка).");
            }
        }

        _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}");

        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, new X509Certificate2(task.CertificatePath));

        // ── Verify private key binding; attempt certutil -repairstore if missing ──
        await VerifyAndRepairPrivateKeyAsync(task, storeLocation);
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
    //  certmgr invocations
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

    /// <summary>
    /// Disk mode: copies the container to <paramref name="destContainerFolder"/>,
    /// places the <c>.cer</c> file next to it (temp copy), then runs
    /// <c>certmgr -inst</c> <b>without</b> <c>-cont</c> so CryptoPro auto-discovers
    /// the container. Removes the temporary <c>.cer</c> copy in a <c>finally</c> block;
    /// the container folder is kept permanently.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrDiskModeAsync(
        string certMgr, string cerPath, string sourceContainer, string containerFolderName,
        string destContainerFolder, string password, string locationArg, int provType)
    {
        Directory.CreateDirectory(destContainerFolder);
        var destContainerDir = Path.Combine(destContainerFolder, containerFolderName);

        var srcFull = Path.GetFullPath(sourceContainer)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var dstFull = Path.GetFullPath(destContainerDir)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(destContainerDir);
            await Task.Run(() => CopyContainerFiles(sourceContainer, destContainerDir));
            _logger.Info($"Контейнер скопирован на диск: {destContainerDir}");
        }
        else
        {
            _logger.Info($"Контейнер уже в целевой папке: {dstFull}");
        }

        // Place .cer next to the container folder so CryptoPro can find both
        var tempCerPath = Path.Combine(destContainerFolder, Path.GetFileName(cerPath));
        File.Copy(cerPath, tempCerPath, overwrite: true);
        _logger.Info($"Режим Диск: .cer скопирован рядом с контейнером: {tempCerPath}");

        try
        {
            var pinArg    = !string.IsNullOrEmpty(password) ? $@" -pin ""{password}""" : string.Empty;
            var pinForLog = !string.IsNullOrEmpty(password) ? @" -pin ""***"""         : string.Empty;

            // No -cont: CryptoPro auto-discovers the container in the same directory as the .cer
            var args   = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinArg} -silent";
            var forLog = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinForLog} -silent";
            _logger.Info($"Запуск (Диск, без -cont): {certMgr} {forLog}");

            var result = await _cryptoProCli.RunAsync(certMgr, args);
            _logger.Info($"certmgr код {result.ExitCode}. Вывод:\n{result.Output}");
            return result;
        }
        finally
        {
            try { File.Delete(tempCerPath); }
            catch (Exception ex) { _logger.Warn($"Не удалось удалить temp .cer {tempCerPath}: {ex.Message}"); }
        }
    }

    /// <summary>
    /// Strategy 2 fallback (registry mode): copies the <c>.cer</c> + container into a
    /// temp directory and runs <c>certmgr -inst</c> <b>without</b> <c>-cont</c>.
    /// CryptoPro auto-discovers the container from the same directory as the certificate.
    /// The temp directory is deleted in a <c>finally</c> block.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrWithTempFolderAsync(
        string certMgr, string cerPath, string sourceContainer, string containerFolderName,
        string password, string locationArg, int provType)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"EcpInstall_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var tempCerPath = Path.Combine(tempDir, Path.GetFileName(cerPath));
            File.Copy(cerPath, tempCerPath, overwrite: true);

            var tempContainerDir = Path.Combine(tempDir, containerFolderName);
            Directory.CreateDirectory(tempContainerDir);
            CopyContainerFiles(sourceContainer, tempContainerDir);

            _logger.Info($"Стратегия 2: temp-папка {tempDir}");

            var pinArg    = !string.IsNullOrEmpty(password) ? $@" -pin ""{password}""" : string.Empty;
            var pinForLog = !string.IsNullOrEmpty(password) ? @" -pin ""***"""         : string.Empty;

            var args   = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinArg} -silent";
            var forLog = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinForLog} -silent";
            _logger.Info($"Запуск (без -cont): {certMgr} {forLog}");

            var result = await _cryptoProCli.RunAsync(certMgr, args);
            _logger.Info($"certmgr код {result.ExitCode}. Вывод:\n{result.Output}");
            return result;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); }
            catch (Exception ex) { _logger.Warn($"Не удалось удалить temp-папку {tempDir}: {ex.Message}"); }
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Container name from name.key
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the logical container name from <c>name.key</c> inside
    /// <paramref name="containerFolder"/>. Tries UTF-16LE (CryptoPro 5) first,
    /// then CP1251 (CryptoPro 4 / older). Falls back to the folder name without
    /// extension if decoding fails.
    /// </summary>
    private string ReadContainerName(string containerFolder)
    {
        var nameKeyPath = Path.Combine(containerFolder, "name.key");
        if (!File.Exists(nameKeyPath))
        {
            var fallback = FolderBaseName(containerFolder);
            _logger.Warn($"name.key не найден в {containerFolder}, используется имя папки: {fallback}");
            return fallback;
        }

        var bytes = File.ReadAllBytes(nameKeyPath);

        var nameUtf16 = TryDecodeContainerName(bytes, Encoding.Unicode);
        if (nameUtf16 is not null)
        {
            _logger.Info($"Имя контейнера из name.key (UTF-16LE): {nameUtf16}");
            return nameUtf16;
        }

        try
        {
            var cp1251 = Encoding.GetEncoding(1251);
            var nameCp1251 = TryDecodeContainerName(bytes, cp1251);
            if (nameCp1251 is not null)
            {
                _logger.Info($"Имя контейнера из name.key (CP1251): {nameCp1251}");
                return nameCp1251;
            }
        }
        catch (NotSupportedException) { }

        var fallbackName = FolderBaseName(containerFolder);
        _logger.Warn($"Не удалось декодировать name.key ({bytes.Length} байт), используется имя папки: {fallbackName}");
        return fallbackName;
    }

    private static string? TryDecodeContainerName(byte[] bytes, Encoding encoding)
    {
        try
        {
            var raw = encoding.GetString(bytes);
            var segments = raw.Split('\0', StringSplitOptions.RemoveEmptyEntries);
            foreach (var seg in segments)
            {
                var trimmed = seg.Trim().Trim('\uFEFF', '\uFFFD');
                if (trimmed.Length >= 3 && trimmed.All(c => !char.IsControl(c) && c != '\uFFFD'))
                    return trimmed;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string FolderBaseName(string folderPath) =>
        Path.GetFileNameWithoutExtension(
            folderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    // ──────────────────────────────────────────────────────────────
    //  Registry container placement
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the logical container name from <c>name.key</c>,
    /// copies key files to <c>%APPDATA%\Crypto Pro\Keys\{logicalName}\</c>,
    /// and returns <c>\\.\REGISTRY\{logicalName}</c>.
    /// The UNC path never contains the <c>.NNN</c> extension.
    /// </summary>
    private async Task<string> PlaceContainerToRegistryAsync(string sourceContainer, string containerName)
    {
        var logicalName = ReadContainerName(sourceContainer);
        _logger.Info($"Логическое имя контейнера: '{logicalName}' (папка: '{containerName}')");

        var keysRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Crypto Pro", "Keys");
        var destination = Path.Combine(keysRoot, logicalName);

        _logger.Info($"Режим реестра: копирование контейнера в {destination}");
        Directory.CreateDirectory(destination);
        await Task.Run(() => CopyContainerFiles(sourceContainer, destination));
        _logger.Info($"Контейнер скопирован: {destination}");

        var uncPath = $@"\\.\REGISTRY\{logicalName}";
        _logger.Info($"UNC-путь контейнера: {uncPath}");
        return uncPath;
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

    /// <summary>
    /// Pre-caches the container password via <c>csptest.exe</c> so that CryptoPro's
    /// interactive PIN dialog is suppressed when certmgr subsequently opens the container.
    /// Errors are logged but never propagated — certmgr will attempt auth on its own.
    /// </summary>
    private async Task CacheContainerPasswordAsync(string certMgrDirectory, string contPath, string password)
    {
        if (string.IsNullOrEmpty(password)) return;

        var cspTestPath = Path.Combine(certMgrDirectory, "csptest.exe");
        if (!File.Exists(cspTestPath))
        {
            _logger.Warn("csptest.exe не найден, пропускаем кэширование пароля.");
            return;
        }

        var args   = $@"-keyset -cont ""{contPath}"" -password ""{password}"" -check";
        var forLog = $@"-keyset -cont ""{contPath}"" -password ""***"" -check";
        _logger.Info($"Кэширование пароля: csptest {forLog}");

        var (exitCode, output) = await RunSystemCommandAsync(cspTestPath, args);
        _logger.Info($"csptest exitCode={exitCode}. Вывод:\n{output}");
        // Non-zero is normal if the container is new — certmgr handles it with -pin.
    }

    /// <summary>
    /// Returns <c>true</c> if <paramref name="path"/> resides on a removable drive
    /// (USB / FAT12 flash drive).  Used to auto-switch disk mode to registry mode so
    /// that certmgr's <c>-pin</c> argument is honoured instead of showing a PIN dialog.
    /// </summary>
    private static bool IsOnRemovableDrive(string path)
    {
        try
        {
            var root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root)) return false;
            return new DriveInfo(root).DriveType == DriveType.Removable;
        }
        catch
        {
            return false;
        }
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
