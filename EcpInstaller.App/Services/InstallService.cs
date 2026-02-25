using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
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
            task.Message = "Установлено";
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
        {
            keyStorageFlags |= X509KeyStorageFlags.MachineKeySet;
        }

        var cert = new X509Certificate2(task.CertificatePath, password, keyStorageFlags);
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        _logger.Info($@"PFX установлен: {task.CertificatePath} в {storeLocation}\My");
        RemoveOldCertificatesExcept(store, cert);
    }

    // ──────────────────────────────────────────────────────────────
    //  CryptoPro CER + container
    // ──────────────────────────────────────────────────────────────

    private async Task InstallCryptoProAsync(SignatureTask task, string password, StoreLocation storeLocation, ContainerLocation containerLocation, string containerFolder)
    {
        EnsureAccess(storeLocation);

        var certMgr = _cryptoProCli.ResolveCertMgrPath();
        if (certMgr is null)
        {
            throw new InvalidOperationException("CryptoPro CSP не найден (certmgr.exe отсутствует). Установите CSP или используйте PFX.");
        }

        if (string.IsNullOrWhiteSpace(task.ContainerPath) || !Directory.Exists(task.ContainerPath))
        {
            throw new InvalidOperationException("Для CER не найден контейнер закрытого ключа рядом с сертификатом.");
        }

        var cspVer = _cryptoProCli.ResolveCspVersion();
        _logger.Info($"CryptoPro CSP версия: {(cspVer > 0 ? cspVer.ToString() : "не определена")}");

        var locationArg = storeLocation == StoreLocation.CurrentUser ? "uMy" : "mMy";
        var sourceContainer = task.ContainerPath!;

        // ── Strategy 1: place container via name.key logical name, pass -cont ──────────────
        _logger.Info("Стратегия 1: установка с -cont (имя из name.key).");
        var strategy1Ok = false;
        string? lastOutput = null;
        int lastExitCode = -1;

        try
        {
            var contUncPath = await PlaceContainerAsync(sourceContainer, containerLocation, containerFolder);
            foreach (var provType in ProvTypes)
            {
                (lastExitCode, lastOutput) = await RunCertMgrInstallAsync(certMgr, task.CertificatePath, contUncPath, password, locationArg, provType);
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

        // ── Strategy 2 (fallback): copy .cer + container to temp dir, run without -cont ──
        if (!strategy1Ok)
        {
            _logger.Info("Стратегия 2: установка без -cont (temp-папка, авто-обнаружение контейнера).");
            var folderName = Path.GetFileName(
                sourceContainer.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

            foreach (var provType in ProvTypes)
            {
                (lastExitCode, lastOutput) = await RunCertMgrWithTempFolderAsync(
                    certMgr, task.CertificatePath, sourceContainer, folderName, password, locationArg, provType);
                if (lastExitCode == 0) break;
                _logger.Warn($"Стратегия 2, certmgr -provtype {provType} завершился с кодом {lastExitCode}.");
            }

            if (lastExitCode != 0)
                throw new InvalidOperationException($"Обе стратегии установки не удались. Последний код: {lastExitCode}.\n{lastOutput}");

            _logger.Info("Стратегия 2 успешна (temp-папка).");
        }

        _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}");

        var cert = new X509Certificate2(task.CertificatePath);
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, cert);
    }

    /// <summary>
    /// Builds and runs a single <c>certmgr -inst</c> invocation, logging
    /// the full command line (PIN masked) and the complete output.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrInstallAsync(
        string certMgr, string cerPath, string contUncPath, string password, string locationArg, int provType)
    {
        var pinArg = !string.IsNullOrEmpty(password) ? $@" -pin ""{password}""" : string.Empty;
        var pinArgForLog = !string.IsNullOrEmpty(password) ? @" -pin ""***""" : string.Empty;

        var args = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pinArg} -silent";
        var argsForLog = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pinArgForLog} -silent";
        _logger.Info($"Запуск: {certMgr} {argsForLog}");

        var result = await _cryptoProCli.RunAsync(certMgr, args);
        _logger.Info($"certmgr код {result.ExitCode}. Вывод:\n{result.Output}");
        return result;
    }

    /// <summary>
    /// Strategy 2 fallback: copies the <c>.cer</c> file and the container folder into a
    /// fresh temp directory, then runs <c>certmgr -inst</c> <b>without</b> <c>-cont</c>.
    /// CryptoPro auto-discovers the container from the same directory as the certificate.
    /// Cleans up the temp directory afterwards regardless of outcome.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrWithTempFolderAsync(
        string certMgr, string cerPath, string sourceContainer, string containerFolderName,
        string password, string locationArg, int provType)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"EcpInstall_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            // Copy .cer into temp dir
            var tempCerPath = Path.Combine(tempDir, Path.GetFileName(cerPath));
            File.Copy(cerPath, tempCerPath, overwrite: true);

            // Copy container folder into temp dir preserving its .NNN name
            var tempContainerDir = Path.Combine(tempDir, containerFolderName);
            Directory.CreateDirectory(tempContainerDir);
            CopyContainerFiles(sourceContainer, tempContainerDir);

            _logger.Info($"Стратегия 2: temp-папка {tempDir}");

            var pinArg = !string.IsNullOrEmpty(password) ? $@" -pin ""{password}""" : string.Empty;
            var pinArgForLog = !string.IsNullOrEmpty(password) ? @" -pin ""***""" : string.Empty;

            // No -cont: certmgr locates the container next to the .cer automatically
            var args = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinArg} -silent";
            var argsForLog = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pinArgForLog} -silent";
            _logger.Info($"Запуск (без -cont): {certMgr} {argsForLog}");

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

        // Try UTF-16LE first (typical for CryptoPro 5)
        var nameUtf16 = TryDecodeContainerName(bytes, Encoding.Unicode);
        if (nameUtf16 is not null)
        {
            _logger.Info($"Имя контейнера из name.key (UTF-16LE): {nameUtf16}");
            return nameUtf16;
        }

        // Fall back to CP1251 (CryptoPro 4 / older)
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
        catch (NotSupportedException) { /* CP1251 not available on this platform */ }

        var fallbackName = FolderBaseName(containerFolder);
        _logger.Warn($"Не удалось декодировать name.key ({bytes.Length} байт), используется имя папки: {fallbackName}");
        return fallbackName;
    }

    /// <summary>
    /// Decodes <paramref name="bytes"/> as a null-terminated string using
    /// <paramref name="encoding"/>, strips BOM / replacement chars, and returns
    /// the first printable segment of 3+ characters; or <c>null</c> on failure.
    /// </summary>
    private static string? TryDecodeContainerName(byte[] bytes, Encoding encoding)
    {
        try
        {
            var raw = encoding.GetString(bytes);
            var segments = raw.Split('\0', StringSplitOptions.RemoveEmptyEntries);
            foreach (var seg in segments)
            {
                // Strip BOM and Unicode replacement character
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
    //  Container placement
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Copies the container to its target location and returns the CryptoPro UNC path.
    /// <list type="bullet">
    ///   <item><b>Registry</b> — copies files to <c>%APPDATA%\Crypto Pro\Keys\{name}\</c>,
    ///         returns <c>\\.\REGISTRY\{name}</c>.</item>
    ///   <item><b>Disk (HDIMAGE)</b> — registers <paramref name="containerFolder"/> as the
    ///         HDIMAGE reader in the CryptoPro registry, copies the container folder there,
    ///         returns <c>\\.\HDIMAGE\{name}</c>.</item>
    /// </list>
    /// </summary>
    private async Task<string> PlaceContainerAsync(
        string sourceContainer, ContainerLocation containerLocation, string containerFolder)
    {
        var containerName = Path.GetFileName(
            sourceContainer.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (containerLocation == ContainerLocation.Registry)
        {
            return await PlaceContainerToRegistryAsync(sourceContainer, containerName);
        }

        return await PlaceContainerToDiskAsync(sourceContainer, containerName, containerFolder);
    }

    /// <summary>
    /// Registry mode: reads the logical container name from <c>name.key</c>,
    /// copies key files to <c>%APPDATA%\Crypto Pro\Keys\{logicalName}\</c>,
    /// returns <c>\\.\REGISTRY\{logicalName}</c>.
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

    /// <summary>
    /// Disk / HDIMAGE mode: register the folder as an HDIMAGE reader, copy the container,
    /// return the HDIMAGE UNC path.
    /// </summary>
    private async Task<string> PlaceContainerToDiskAsync(
        string sourceContainer, string containerName, string containerFolder)
    {
        // CryptoPro can only open disk containers through a registered HDIMAGE reader.
        // Writing to HKLM requires administrator privileges.
        if (!WindowsPrincipalHelper.IsAdministrator())
        {
            _logger.Warn("Режим 'Диск' может потребовать прав администратора для регистрации считывателя HDIMAGE.");
        }

        EnsureHdImageReaderRegistered(containerFolder);

        Directory.CreateDirectory(containerFolder);
        var diskDestination = Path.Combine(containerFolder, containerName);

        var srcFull = Path.GetFullPath(sourceContainer)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var dstFull = Path.GetFullPath(diskDestination)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(diskDestination);
            await Task.Run(() => CopyContainerFiles(sourceContainer, diskDestination));
            _logger.Info($"Контейнер скопирован на диск: {diskDestination}");
        }
        else
        {
            _logger.Info($"Контейнер уже в целевой папке: {dstFull}");
        }

        // HDIMAGE is the CryptoPro reader name registered for containerFolder.
        var uncPath = $@"\\.\HDIMAGE\{containerName}";
        _logger.Info($"UNC-путь контейнера: {uncPath}");
        return uncPath;
    }

    // ──────────────────────────────────────────────────────────────
    //  HDIMAGE reader registration
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Ensures the target folder is registered as the HDIMAGE reader in the CryptoPro
    /// registry so that <c>certmgr -cont "\\.\HDIMAGE\…"</c> can locate the container.
    /// Writes to both the native and WOW6432Node keys for x64/x86 compatibility.
    /// </summary>
    private void EnsureHdImageReaderRegistered(string containerFolder)
    {
        var folder = Path.GetFullPath(containerFolder)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        string[] regPaths =
        [
            @"SOFTWARE\Crypto Pro\Settings\HDImage",
            @"SOFTWARE\WOW6432Node\Crypto Pro\Settings\HDImage"
        ];

        var registered = false;
        foreach (var regPath in regPaths)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(regPath, writable: true);
                if (key is null) continue;

                var existing = key.GetValue("Path") as string;
                if (string.Equals(existing?.TrimEnd('\\', '/'), folder, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.Info($"Считыватель HDIMAGE уже зарегистрирован: {folder}");
                    return;
                }

                key.SetValue("Path", folder, Microsoft.Win32.RegistryValueKind.String);
                _logger.Info($"Считыватель HDIMAGE зарегистрирован: {folder} (HKLM\\{regPath})");
                registered = true;
            }
            catch (UnauthorizedAccessException)
            {
                _logger.Warn($"Нет прав записи в HKLM\\{regPath}. " +
                             "Запустите от администратора или используйте режим Реестр.");
            }
            catch (Exception ex)
            {
                _logger.Warn($"Ошибка регистрации считывателя HDIMAGE: {ex.Message}");
            }
        }

        if (registered)
        {
            // Brief pause so CryptoPro CSP picks up the new reader from the registry.
            Thread.Sleep(500);
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  File helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>Copies all files from <paramref name="sourceDir"/> into <paramref name="destDir"/> (flat, no recursion).</summary>
    private static void CopyContainerFiles(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir))
        {
            File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)), overwrite: true);
        }
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
        {
            throw new InvalidOperationException("LocalMachine поддерживается только на Windows.");
        }

        if (storeLocation == StoreLocation.LocalMachine && !WindowsPrincipalHelper.IsAdministrator())
        {
            throw new OperationCanceledException("Для LocalMachine нужны права администратора. Выберите CurrentUser для установки без админа.");
        }
    }
}
