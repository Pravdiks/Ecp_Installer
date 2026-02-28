using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using Microsoft.Win32;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Automation;

namespace EcpInstaller.App.Services;

public sealed class InstallService
{
    /// <summary>provtype fallback order: GOST-2012-256, GOST-2001, GOST-2012-512.</summary>
    private static readonly int[] ProvTypes = [80, 75, 81];

    private readonly AppLogger _logger;
    private readonly CryptoProCli _cryptoProCli;

    /// <summary>Вариант параметра пароля для КриптоПро: "-pin" или "-passwd" (разные версии CSP).</summary>
    private string _cryptoProPasswordOption = "pin";

    private object? _savedRngValue;
    private bool _rngWasAbsent;

    public InstallService(AppLogger logger, CryptoProCli cryptoProCli)
    {
        _logger = logger;
        _cryptoProCli = cryptoProCli;
    }

    // ──────────────────────────────────────────────────────────────
    //  RNG type override: biological → software
    // ──────────────────────────────────────────────────────────────

    private static readonly string[] RngRegistryPaths =
    [
        @"SOFTWARE\Crypto Pro\Cryptography\CurrentVersion\Parameters",
        @"SOFTWARE\Crypto Pro\Settings",
    ];

    /// <summary>
    /// Switches CryptoPro RNG from biological (mouse movement) to software PRNG.
    /// Call before the install loop; call <see cref="RestoreRng"/> after.
    /// </summary>
    public void SetSoftwareRng()
    {
        foreach (var path in RngRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: true)
                                ?? Registry.CurrentUser.CreateSubKey(path);
                _savedRngValue = key.GetValue("RNGType");
                _rngWasAbsent = _savedRngValue is null;
                key.SetValue("RNGType", 2, RegistryValueKind.DWord);
                _logger.Info($"RNG переключён на программный (RNGType=2) в {path}");
                return;
            }
            catch (Exception ex)
            {
                _logger.Warn($"Не удалось записать RNGType в {path}: {ex.Message}");
            }
        }
        _logger.Warn("Не удалось переключить RNG ни в HKLM, ни в HKCU. Био ДСЧ может появиться.");
    }

    /// <summary>Restores the original RNG setting saved by <see cref="SetSoftwareRng"/>.</summary>
    public void RestoreRng()
    {
        foreach (var path in RngRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: true)
                                ?? Registry.CurrentUser.OpenSubKey(path, writable: true);
                if (key is null) continue;

                if (_rngWasAbsent)
                    key.DeleteValue("RNGType", throwOnMissingValue: false);
                else if (_savedRngValue is not null)
                    key.SetValue("RNGType", _savedRngValue, RegistryValueKind.DWord);

                _logger.Info($"RNG восстановлен в {path}");
                return;
            }
            catch (Exception ex)
            {
                _logger.Warn($"Не удалось восстановить RNGType в {path}: {ex.Message}");
            }
        }
    }

    public async Task InstallAsync(
        SignatureTask task,
        string password,
        StoreLocation storeLocation,
        ContainerLocation containerLocation,
        string containerFolder,
        bool enablePinWatcher = true)
    {
        task.Status = SignatureTaskStatus.Running;
        task.Message = "Установка...";

        // Фоновый триггер: если появится окно «Аутентификация - КриптоПро CSP»,
        // он автоматически попробует работать с ним (галочки/ОК, ввод PIN — если разрешено).
        CancellationTokenSource? pinWatcherCts = null;
        Task pinWatcherTask = Task.CompletedTask;
        if (enablePinWatcher && !string.IsNullOrWhiteSpace(password))
        {
            pinWatcherCts  = new CancellationTokenSource();
            pinWatcherTask = StartCryptoProPinWatcherAsync(password, pinWatcherCts.Token);
        }

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
            var msg = ex.Message;
            if (msg.Contains("пароль", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                ex is System.Security.Cryptography.CryptographicException)
                msg = "Неверный пароль контейнера/PFX";
            task.Message = $"Ошибка: {msg}";
            _logger.Error($"Ошибка установки '{task.DisplayName}': {ex}");
        }
        finally
        {
            if (pinWatcherCts is not null)
            {
                pinWatcherCts.Cancel();
                try { await pinWatcherTask.ConfigureAwait(false); } catch { }
            }
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
        // ШАГ 1: Определяем папку реестра КриптоПро (из реестра Windows).
        // ═══════════════════════════════════════════════════════════
        var keysRoot = GetCryptoProKeysFolder();

        // ═══════════════════════════════════════════════════════════
        // ШАГ 2: Копируем контейнер в папку КриптоПро и пишем
        // метаданные в реестр. Без csptest -newkeyset (тихий режим).
        // ═══════════════════════════════════════════════════════════
        var (contUncPath, regName) = await ImportContainerToRegistryAsync(
            task, certMgr, keysRoot, password);

        // Пароль из поля «Пароль контейнера/PFX» передаётся в certmgr без предпроверки через csptest,
        // т.к. csptest с -provtype может отвергать верный пароль (при ручной установке через КриптоПро тот же пароль принимается).

        // ═══════════════════════════════════════════════════════════
        // ШАГ 3: Режим "Диск" — дополнительно копируем контейнер
        // в указанную папку (для хранения). Не критично для установки.
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

                // #region agent log H1
                try
                {
                    var payload4 = $"{{\"sessionId\":\"d11374\",\"hypothesisId\":\"H1\",\"location\":\"InstallService.cs:DiskBackup\",\"message\":\"disk backup paths\",\"data\":{{\"certName\":\"{task.DisplayName?.Replace("\"", "\\\"")}\",\"sourceContainer\":\"{srcFull.Replace("\\", "\\\\")}\",\"diskDest\":\"{dstFull.Replace("\\", "\\\\")}\",\"actualFolder\":\"{actualFolder.Replace("\\", "\\\\")}\",\"srcEqualsDst\":{string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase).ToString().ToLower()}}},\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}";
                    File.AppendAllText("debug-d11374.log", payload4 + "\n");
                }
                catch { }
                // #endregion

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
        // ШАГ 4: Проверяем что КриптоПро видит контейнер (csptest).
        // ═══════════════════════════════════════════════════════════
        await VerifyContainerVisibleAsync(certMgr, contUncPath, password);

        // ═══════════════════════════════════════════════════════════
        // ШАГ 5: Диагностика — состояние папки контейнера перед certmgr.
        // ═══════════════════════════════════════════════════════════
        LogContainerState(Path.Combine(keysRoot, regName), contUncPath);

        // ═══════════════════════════════════════════════════════════
        // ШАГ 5.5: Предварительная авторизация контейнера через csptest.
        // Это кэширует PIN в CryptoPro, чтобы certmgr не показывал диалог.
        // ═══════════════════════════════════════════════════════════
        await PreAuthenticateContainerAsync(certMgr, contUncPath, password);

        // ═══════════════════════════════════════════════════════════
        // ШАГ 6: certmgr с реестровым UNC-путём.
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

        // Если реестровый путь не открылся — пробуем HDIMAGE (файловый контейнер в папке Keys).
        if (lastExitCode != 0)
        {
            var contHdImage = $@"\\.\HDIMAGE\{regName}";
            _logger.Info($"Пробуем путь HDIMAGE: {contHdImage}");
            foreach (var provType in ProvTypes)
            {
                (lastExitCode, lastOutput) = await RunCertMgrInstallAsync(
                    certMgr, task.CertificatePath, contHdImage, password, locationArg, provType);
                if (lastExitCode == 0)
                {
                    _logger.Info($"certmgr с HDIMAGE успешен (provtype={provType}).");
                    break;
                }
            }
        }

        // ═══════════════════════════════════════════════════════════
        // ШАГ 7: Fallback — установка без -cont если все попытки
        // с реестровым UNC-путём провалились.
        // ═══════════════════════════════════════════════════════════
        if (lastExitCode != 0)
        {
            _logger.Warn($"Все попытки с -cont провалились (код {lastExitCode}). Пробуем fallback без -cont...");
            var fallbackOk = await TryInstallWithoutContAsync(
                certMgr, locationArg, task.CertificatePath, keysRoot, password);
            if (!fallbackOk)
            {
                var msg = lastOutput ?? "";
                if (lastExitCode == -2146893802 || msg.Contains("парол", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("pin", StringComparison.OrdinalIgnoreCase) || msg.Contains("0x80090005", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Неверный пароль контейнера");
                throw new InvalidOperationException(
                    $"certmgr завершился с кодом {lastExitCode}.\n{lastOutput}");
            }
            _logger.Info("Установлено через fallback (без -cont).");
        }
        else
        {
            _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}");
            _logger.Info($"UNC контейнера: {contUncPath}");
        }

        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, new X509Certificate2(task.CertificatePath));

        // ═══════════════════════════════════════════════════════════
        // ШАГ 8: Проверка привязки закрытого ключа.
        // Если не привязан — certutil -repairstore (может появиться окно пароля КриптоПро).
        // ═══════════════════════════════════════════════════════════
        await VerifyAndRepairPrivateKeyAsync(
            task, storeLocation, certMgr, contUncPath, password, locationArg);
    }

    // ──────────────────────────────────────────────────────────────
    //  Keys folder discovery
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the CryptoPro Keys folder for the current user.
    /// Reads <c>HKCU\Software\Crypto Pro\Settings\KeysDirectory</c> first;
    /// falls back to the standard <c>%APPDATA%\Crypto Pro\Keys</c> path.
    /// </summary>
    private string GetCryptoProKeysFolder()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Crypto Pro\Settings");
            if (key != null)
            {
                var keysPath = key.GetValue("KeysDirectory") as string;
                if (!string.IsNullOrEmpty(keysPath) && Directory.Exists(keysPath))
                {
                    _logger.Info($"Keys folder из реестра: {keysPath}");
                    return keysPath;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warn($"Не удалось прочитать KeysDirectory из реестра: {ex.Message}");
        }

        var standard = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Crypto Pro", "Keys");
        _logger.Info($"Keys folder стандартный: {standard}");
        Directory.CreateDirectory(standard);
        return standard;
    }

    // ──────────────────────────────────────────────────────────────
    //  Container import into CryptoPro registry
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Imports the container into the CryptoPro registry provider by copying key files
    /// into the CryptoPro Keys folder and writing registry metadata.
    /// No <c>csptest -newkeyset</c> is used — existing keys are copied as-is,
    /// which avoids the biological RNG dialog entirely.
    /// Returns <c>(\\.\REGISTRY\{name}, {name})</c>.
    /// </summary>
    private async Task<(string UncPath, string RegName)> ImportContainerToRegistryAsync(
        SignatureTask task, string certMgrPath, string keysRoot, string password)
    {
        var sourceContainerPath = task.ContainerPath!;
        var rawName = Path.GetFileName(
            sourceContainerPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        var ext     = Path.GetExtension(rawName);
        var regName = ext.Length > 1 && ext[1..].All(char.IsDigit)
            ? Path.GetFileNameWithoutExtension(rawName)
            : rawName;

        var contUncPath = $@"\\.\REGISTRY\{regName}";
        _logger.Info($"Импорт контейнера: {sourceContainerPath} → {contUncPath}");

        // #region agent log H1/H2/H5
        try
        {
            var srcFiles = Directory.Exists(sourceContainerPath)
                ? string.Join(", ", Directory.GetFiles(sourceContainerPath).Select(f => $"{Path.GetFileName(f)}({new FileInfo(f).Length}b)"))
                : "ПАПКА НЕ НАЙДЕНА";
            var nameKeyPath = Path.Combine(sourceContainerPath, "name.key");
            var nameKeyHex = File.Exists(nameKeyPath)
                ? BitConverter.ToString(File.ReadAllBytes(nameKeyPath)).Replace("-", "")
                : "ОТСУТСТВУЕТ";
            var payload = $"{{\"sessionId\":\"d11374\",\"hypothesisId\":\"H1_H2_H5\",\"location\":\"InstallService.cs:ImportContainerToRegistry\",\"message\":\"source container info\",\"data\":{{\"certName\":\"{task.DisplayName?.Replace("\"", "\\\"")}\",\"containerPath\":\"{sourceContainerPath.Replace("\\", "\\\\")}\",\"rawName\":\"{rawName}\",\"regName\":\"{regName}\",\"srcFiles\":\"{srcFiles.Replace("\"", "\\\"")}\",\"nameKeyHex\":\"{nameKeyHex}\"}},\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}";
            File.AppendAllText("debug-d11374.log", payload + "\n");
        }
        catch { }
        // #endregion

        var cspTestPath = Path.Combine(Path.GetDirectoryName(certMgrPath)!, "csptest.exe");

        var registered = await TryCopyAndRegisterContainerAsync(
            sourceContainerPath, regName, contUncPath, keysRoot, cspTestPath, password);
        if (registered)
        {
            _logger.Info($"Копирование + реестр успешно: {contUncPath}");
            return (contUncPath, regName);
        }

        _logger.Warn("Контейнер скопирован, но csptest не подтвердил видимость. " +
            "certmgr fallback попробует без -cont.");
        return (contUncPath, regName);
    }

    // ── Копирование файлов + запись в реестр Windows ─

    /// <summary>Определяет, какой параметр пароля поддерживает установленный КриптоПро: -pin или -passwd.</summary>
    private async Task DetectAndSetPasswordOptionAsync(string cspTestPath, string contUncPath, string password)
    {
        var (codePin, outputPin) = await RunSystemCommandAsync(cspTestPath, $@"-keyset -cont ""{contUncPath}"" -pin ""{password}"" -info -silent");
        if (codePin == 0)
        {
            _cryptoProPasswordOption = "pin";
            _logger.Info("КриптоПро использует параметр -pin для пароля.");
            return;
        }
        var (codePasswd, outputPasswd) = await RunSystemCommandAsync(cspTestPath, $@"-keyset -cont ""{contUncPath}"" -passwd ""{password}"" -info -silent");
        if (codePasswd == 0)
        {
            _cryptoProPasswordOption = "passwd";
            _logger.Info("КриптоПро использует параметр -passwd для пароля.");
            return;
        }
        var outPinLower = outputPin.ToLowerInvariant();
        var outPasswdLower = outputPasswd.ToLowerInvariant();
        bool pinRejected = (outPinLower.Contains("invalid option") || outPinLower.Contains("unrecognized")) && outPinLower.Contains("pin");
        bool passwdRejected = (outPasswdLower.Contains("invalid option") || outPasswdLower.Contains("unrecognized")) && outPasswdLower.Contains("passwd");
        if (pinRejected && !passwdRejected)
        {
            _cryptoProPasswordOption = "passwd";
            _logger.Info("КриптоПро не поддерживает -pin, выбран параметр -passwd для пароля.");
            return;
        }
        if (passwdRejected)
        {
            _cryptoProPasswordOption = "pin";
            _logger.Info("КриптоПро не поддерживает -passwd, выбран параметр -pin для пароля.");
            return;
        }
        _cryptoProPasswordOption = "pin";
    }

    private async Task<bool> TryCopyAndRegisterContainerAsync(
        string sourceContainerPath, string regName, string contUncPath,
        string keysRoot, string cspTestPath, string password)
    {
        try
        {
            var destFolder = Path.Combine(keysRoot, regName);
            if (Directory.Exists(destFolder))
                Directory.Delete(destFolder, recursive: true);
            Directory.CreateDirectory(destFolder);

            _logger.Info($"Копирование контейнера: {sourceContainerPath} → {destFolder}");
            foreach (var f in Directory.EnumerateFiles(sourceContainerPath))
            {
                var dest = Path.Combine(destFolder, Path.GetFileName(f));
                File.Copy(f, dest, overwrite: true);
                File.SetAttributes(dest, FileAttributes.Normal);
                _logger.Info($"  Скопирован: {Path.GetFileName(dest)} ({new FileInfo(dest).Length} байт)");
            }

            // Проверить наличие критичных файлов.
            foreach (var req in new[] { "primary.key", "header.key", "masks.key" })
            {
                var reqPath = Path.Combine(destFolder, req);
                if (!File.Exists(reqPath))
                    _logger.Warn($"  ВНИМАНИЕ: файл отсутствует: {req}");
                else
                    _logger.Info($"  Файл OK: {req} ({new FileInfo(reqPath).Length} байт)");
            }

            // Записать метаданные в реестр КриптоПро.
            RegisterContainerInRegistry(regName, destFolder);

            await Task.Delay(1500);

            // #region agent log H2/H4/H5
            try
            {
                var destFiles = Directory.Exists(destFolder)
                    ? string.Join(", ", Directory.GetFiles(destFolder).Select(f => $"{Path.GetFileName(f)}({new FileInfo(f).Length}b)"))
                    : "ПАПКА НЕ НАЙДЕНА";
                var destNameKeyPath = Path.Combine(destFolder, "name.key");
                var destNameKeyHex = File.Exists(destNameKeyPath)
                    ? BitConverter.ToString(File.ReadAllBytes(destNameKeyPath)).Replace("-", "")
                    : "ОТСУТСТВУЕТ";
                var payload2 = $"{{\"sessionId\":\"d11374\",\"hypothesisId\":\"H2_H4_H5\",\"location\":\"InstallService.cs:TryCopyAndRegister\",\"message\":\"dest folder after copy\",\"data\":{{\"regName\":\"{regName}\",\"destFolder\":\"{destFolder.Replace("\\", "\\\\")}\",\"destFiles\":\"{destFiles.Replace("\"", "\\\"")}\",\"destNameKeyHex\":\"{destNameKeyHex}\",\"keysRoot\":\"{destFolder.Replace("\\", "\\\\")}\"}},\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}";
                File.AppendAllText("debug-d11374.log", payload2 + "\n");
            }
            catch { }
            // #endregion

            // Проверить видимость через csptest (если есть).
            if (File.Exists(cspTestPath))
            {
                if (!string.IsNullOrEmpty(password))
                    await DetectAndSetPasswordOptionAsync(cspTestPath, contUncPath, password);

                var args = string.IsNullOrEmpty(password)
                    ? $@"-keyset -cont ""{contUncPath}"" -info -silent"
                    : $@"-keyset -cont ""{contUncPath}"" -{_cryptoProPasswordOption} ""{password}"" -info -silent";

                var code = await RunProcessGetCodeAsync(cspTestPath, args);
                _logger.Info($"После копирования + реестр: csptest code={code}");
                return code == 0;
            }
            _logger.Info("csptest.exe не найден — доверяем копированию файлов.");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Warn($"TryCopyAndRegisterContainer ошибка: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Writes container metadata into Windows registry paths used by CryptoPro 5
    /// so the provider can locate the container folder.
    /// </summary>
    private void RegisterContainerInRegistry(string containerName, string folderPath)
    {
        string[] regPaths =
        [
            $@"Software\Crypto Pro\Settings\Users\{containerName}",
            $@"Software\Crypto Pro\Settings\Keys\{containerName}",
        ];

        foreach (var regPath in regPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(regPath);
                if (key != null)
                {
                    key.SetValue("Path", folderPath);
                    key.SetValue("Name", containerName);
                    _logger.Info($"Реестр записан: HKCU\\{regPath}");
                }
            }
            catch (Exception ex)
            {
                _logger.Warn($"Не удалось записать реестр {regPath}: {ex.Message}");
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Container visibility check (csptest)
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs <c>csptest -keyset -cont "{contUncPath}" -info</c> and logs whether
    /// CryptoPro can see the container. Errors are logged but never propagated.
    /// </summary>
    private async Task VerifyContainerVisibleAsync(string certMgrPath, string contUncPath, string password)
    {
        var cspTestPath = Path.Combine(Path.GetDirectoryName(certMgrPath)!, "csptest.exe");
        if (!File.Exists(cspTestPath))
        {
            _logger.Warn("csptest.exe не найден, пропускаем проверку видимости контейнера.");
            return;
        }

        var args = string.IsNullOrEmpty(password)
            ? $@"-keyset -cont ""{contUncPath}"" -info -silent"
            : $@"-keyset -cont ""{contUncPath}"" -{_cryptoProPasswordOption} ""{password}"" -info -silent";
        _logger.Info($"Проверка видимости контейнера: csptest {args}");

        var (exitCode, output) = await RunSystemCommandAsync(cspTestPath, args);
        _logger.Info($"csptest verify exitCode={exitCode}. Вывод:\n{output}");

        if (exitCode != 0)
            _logger.Warn($"КриптоПро НЕ ВИДИТ контейнер {contUncPath}! (csptest код {exitCode})");
        else
            _logger.Info($"КриптоПро ВИДИТ контейнер {contUncPath} ✓");
    }

    // ──────────────────────────────────────────────────────────────
    //  Pre-certmgr diagnostic log
    // ──────────────────────────────────────────────────────────────

    private void LogContainerState(string destFolder, string contUncPath)
    {
        _logger.Info("Состояние контейнера перед certmgr:");
        _logger.Info($"  destFolder  = {destFolder}");
        _logger.Info($"  Существует  = {Directory.Exists(destFolder)}");
        if (Directory.Exists(destFolder))
        {
            var files = Directory.GetFiles(destFolder);
            _logger.Info($"  Файлов      = {files.Length}");
            foreach (var f in files)
                _logger.Info($"    {Path.GetFileName(f)} ({new FileInfo(f).Length} байт)");
        }
        _logger.Info($"  contUncPath = {contUncPath}");
    }

    // ──────────────────────────────────────────────────────────────
    //  Container folder helpers (disk mode)
    // ──────────────────────────────────────────────────────────────

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
    /// Verifies that the installed certificate has a linked private key.
    /// If not linked after a pause, runs <c>certutil -repairstore</c> (with CRYPT_SILENT)
    /// to repair the key link. Может появиться окно «Аутентификация - КриптоПро CSP» для ввода пароля.
    /// </summary>
    private async Task VerifyAndRepairPrivateKeyAsync(
        SignatureTask task, StoreLocation storeLocation,
        string certMgr, string contUncPath, string password, string locationArg)
    {
        var thumbprint = GetCertThumbprint(task.CertificatePath);
        _logger.Info($"Thumbprint: {thumbprint}");

        await Task.Delay(2000);

        var hasKey = CheckPrivateKeyLinked(thumbprint, storeLocation);
        _logger.Info($"HasPrivateKey (без repairstore): {hasKey}");

        if (!hasKey)
        {
            _logger.Info("Попытка привязки ключа через certutil -repairstore (таймаут 15 сек)...");
            var storeArg = storeLocation == StoreLocation.LocalMachine ? "-machine" : "-user";
            var repairArgs   = $"-repairstore {storeArg} My \"{thumbprint}\"";
            var certutilPath = "certutil";

            var (repairCode, repairOut) = await RunRepairStoreCommandAsync(certutilPath, repairArgs, 15_000);
            var repairOutSafe = repairOut ?? "";
            _logger.Info($"certutil -repairstore код {repairCode}. Вывод:\n{repairOutSafe}");
            if (repairCode == -1)
                _logger.Warn("certutil -repairstore таймаут 15 сек — пропускаем.");
            if (repairOutSafe.Contains("0x80090009", StringComparison.OrdinalIgnoreCase) || repairOutSafe.Contains("NTE_BAD_FLAGS", StringComparison.OrdinalIgnoreCase))
                _logger.Warn("КриптоПро вернул NTE_BAD_FLAGS при тихой привязке ключа. Сертификат установлен; при необходимости привяжите ключ вручную через оснастку сертификатов.");

            await Task.Delay(1000);
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
    //  Pre-authentication: unlock container PIN before certmgr
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Проверяет пароль контейнера через csptest. Если пароль неверный, возвращает false —
    /// тогда certmgr не вызывается и окно КриптоПро не открывается.
    /// </summary>
    private async Task<bool> ValidateContainerPasswordAsync(
        string certMgrPath, string contUncPath, string password)
    {
        if (string.IsNullOrEmpty(password)) return true;

        var cspTestPath = Path.Combine(Path.GetDirectoryName(certMgrPath)!, "csptest.exe");
        if (!File.Exists(cspTestPath))
        {
            _logger.Warn("csptest.exe не найден — проверка пароля пропущена.");
            return true;
        }

        foreach (var provType in ProvTypes)
        {
            var args = $@"-keyset -cont ""{contUncPath}"" -provtype {provType} -{_cryptoProPasswordOption} ""{password}"" -info -silent";
            var code = await RunProcessGetCodeAsync(cspTestPath, args, 8_000);
            if (code == 0)
            {
                _logger.Info($"Пароль контейнера верный (provtype={provType}).");
                return true;
            }
        }

        _logger.Warn("Пароль контейнера неверный (csptest не принял PIN).");
        return false;
    }

    /// <summary>
    /// Calls <c>csptest -keyset</c> with the provided PIN so CryptoPro caches the
    /// password internally. After this, certmgr won't show the PIN dialog.
    /// Tries every provtype in order; stops on first success.
    /// </summary>
    private async Task PreAuthenticateContainerAsync(
        string certMgrPath, string contUncPath, string password)
    {
        if (string.IsNullOrEmpty(password)) return;

        var cspTestPath = Path.Combine(Path.GetDirectoryName(certMgrPath)!, "csptest.exe");
        if (!File.Exists(cspTestPath))
        {
            _logger.Warn("csptest.exe не найден — предварительная авторизация PIN пропущена.");
            return;
        }

        _logger.Info("Предварительная авторизация контейнера с паролем...");

        foreach (var provType in ProvTypes)
        {
            var args   = $@"-keyset -cont ""{contUncPath}"" -provtype {provType} -{_cryptoProPasswordOption} ""{password}"" -silent";
            var forLog = $@"-keyset -cont ""{contUncPath}"" -provtype {provType} -{_cryptoProPasswordOption} ""***"" -silent";
            _logger.Info($"csptest (pre-auth, provtype={provType}): {forLog}");

            var code = await RunProcessGetCodeAsync(cspTestPath, args, 8_000);
            _logger.Info($"csptest pre-auth code={code} (provtype={provType})");

            if (code == 0)
            {
                _logger.Info($"Пароль кэширован КриптоПро (provtype={provType}).");
                return;
            }
        }

        _logger.Warn("Предварительная авторизация не удалась — certmgr может запросить пароль вручную.");
    }

    // ──────────────────────────────────────────────────────────────
    //  certmgr invocations
    // ──────────────────────────────────────────────────────────────

    private async Task<(int ExitCode, string Output)> RunCertMgrInstallAsync(
        string certMgr, string cerPath, string contUncPath,
        string password, string locationArg, int provType)
    {
        var pwdArg    = !string.IsNullOrEmpty(password) ? $@" -{_cryptoProPasswordOption} ""{password}""" : string.Empty;
        var pwdForLog = !string.IsNullOrEmpty(password) ? $@" -{_cryptoProPasswordOption} ""***"""         : string.Empty;

        var args   = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pwdArg} -silent";
        var forLog = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType}{pwdForLog} -silent";
        _logger.Info($"Запуск: {certMgr} {forLog}");

        var result = await _cryptoProCli.RunAsync(certMgr, args);
        _logger.Info($"certmgr код {result.ExitCode}. Вывод:\n{result.Output}");
        return result;
    }

    /// <summary>
    /// Fallback: places the <c>.cer</c> file directly inside <paramref name="keysRoot"/>
    /// and runs certmgr <b>without</b> <c>-cont</c> so CryptoPro auto-discovers
    /// the container subfolder. Temp <c>.cer</c> is deleted in a <c>finally</c> block.
    /// </summary>
    private async Task<bool> TryInstallWithoutContAsync(
        string certMgr, string locationArg, string cerPath,
        string keysRoot, string password)
    {
        var tempCerPath = Path.Combine(keysRoot, Path.GetFileName(cerPath));
        File.Copy(cerPath, tempCerPath, overwrite: true);

        try
        {
            foreach (var provType in ProvTypes)
            {
                var pwdArg    = !string.IsNullOrEmpty(password) ? $@" -{_cryptoProPasswordOption} ""{password}""" : string.Empty;
                var pwdForLog = !string.IsNullOrEmpty(password) ? $@" -{_cryptoProPasswordOption} ""***"""         : string.Empty;

                var args   = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pwdArg} -silent";
                var forLog = $@"-inst -store {locationArg} -file ""{tempCerPath}"" -provtype {provType}{pwdForLog} -silent";
                _logger.Info($"Fallback (без -cont): {certMgr} {forLog}");

                var (exitCode, output) = await _cryptoProCli.RunAsync(certMgr, args);
                _logger.Info($"Fallback certmgr код {exitCode}. Вывод:\n{output}");

                if (exitCode == 0)
                {
                    _logger.Info($"Fallback успешен с provtype={provType}.");
                    return true;
                }
                _logger.Warn($"Fallback certmgr -provtype {provType} завершился с кодом {exitCode}.");
            }
            return false;
        }
        finally
        {
            try { File.Delete(tempCerPath); }
            catch (Exception ex) { _logger.Warn($"Не удалось удалить temp .cer {tempCerPath}: {ex.Message}"); }
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  CryptoPro PIN dialog automation
    // ──────────────────────────────────────────────────────────────

    private Task StartCryptoProPinWatcherAsync(string password, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(password))
            return Task.CompletedTask;

        return Task.Run(async () =>
        {
            const int retryWindowMs = 5000;
            IntPtr lastHandled = IntPtr.Zero;
            long lastHandledFirstSeenUtcTicks = 0;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    var hWnd = FindWindow(null, "Аутентификация - КриптоПро CSP");
                    if (hWnd == IntPtr.Zero)
                    {
                        lastHandled = IntPtr.Zero;
                        lastHandledFirstSeenUtcTicks = 0;
                    }
                    else
                    {
                        long now = DateTime.UtcNow.Ticks;
                        if (hWnd != lastHandled)
                        {
                            lastHandled = hWnd;
                            lastHandledFirstSeenUtcTicks = now;
                        }
                        var elapsedMs = (int)((now - lastHandledFirstSeenUtcTicks) / TimeSpan.TicksPerMillisecond);
                        if (elapsedMs > retryWindowMs)
                            continue;

                        var (filled, textLen) = await HandleCryptoProAuthWindowAsync(hWnd, password);
                        if (filled || textLen > 0)
                            lastHandled = IntPtr.Zero;
                    }
                }
                catch
                {
                    // Игнорируем любые ошибки автоматики, чтобы не ронять установку.
                }

                try
                {
                    await Task.Delay(200, token);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    /// <summary>
    /// Автоматически заполняет диалог «Аутентификация - КриптоПро CSP»:
    /// вводит пароль (WM_SETTEXT → UIA ValuePattern → SendInput), ставит галочки «Сохранить пароль», при отсутствии «Неверный пароль» нажимает OK.
    /// Возвращает (filled, textLen): успех заполнения и текущую длину текста в поле PIN.
    /// </summary>
    private async Task<(bool filled, int textLen)> HandleCryptoProAuthWindowAsync(IntPtr hWnd, string password)
    {
        const int WM_GETTEXTLENGTH = 0x000E;

        try
        {
            LogCryptoProPinDiagnostics(hWnd, "auto-fill CryptoPro PIN started");

            if (!IsWindow(hWnd))
                return (false, 0);

            await Task.Delay(400);

            var editCandidates = new List<(IntPtr hwnd, int style, int area)>();
            IntPtr saveAppHandle = IntPtr.Zero;
            IntPtr saveSystemHandle = IntPtr.Zero;
            IntPtr okHandle = IntPtr.Zero;
            bool hasBadPasswordWarning = false;

            EnumChildWindows(hWnd, (child, _) =>
            {
                var cls = GetClassNameSafe(child);
                if (string.Equals(cls, "Edit", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsWindowVisible(child) && IsWindowEnabled(child))
                    {
                        int style = (int)GetWindowLong(child, GWL_STYLE);
                        if (!GetWindowRect(child, out var rect))
                            return true;
                        int area = (rect.Right - rect.Left) * (rect.Bottom - rect.Top);
                        editCandidates.Add((child, style, area));
                    }
                }
                else if (string.Equals(cls, "Button", StringComparison.OrdinalIgnoreCase))
                {
                    var text = GetWindowTextSafe(child);
                    if (text.Contains("Сохранить пароль в приложении", StringComparison.OrdinalIgnoreCase))
                        saveAppHandle = child;
                    else if (text.Contains("Сохранить пароль в системе", StringComparison.OrdinalIgnoreCase))
                        saveSystemHandle = child;
                    else if (string.Equals(text, "OK", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(text, "ОК", StringComparison.OrdinalIgnoreCase))
                        okHandle = child;
                }
                else if (string.Equals(cls, "Static", StringComparison.OrdinalIgnoreCase))
                {
                    var text = GetWindowTextSafe(child);
                    if (text.Contains("Неверный пароль", StringComparison.OrdinalIgnoreCase))
                        hasBadPasswordWarning = true;
                }
                return true;
            }, IntPtr.Zero);

            IntPtr editHandle = IntPtr.Zero;
            if (editCandidates.Count > 0)
            {
                var passwordStyle = editCandidates.FirstOrDefault(c => (c.style & ES_PASSWORD) != 0);
                if (passwordStyle.hwnd != IntPtr.Zero)
                    editHandle = passwordStyle.hwnd;
                else
                    editHandle = editCandidates.OrderByDescending(c => c.area).First().hwnd;
            }

            LogCryptoProPinDiagnostics(hWnd, "controls detected",
                editFound: editHandle != IntPtr.Zero,
                saveApp: saveAppHandle != IntPtr.Zero,
                saveSystem: saveSystemHandle != IntPtr.Zero,
                ok: okHandle != IntPtr.Zero,
                badWarning: hasBadPasswordWarning);

            if (hasBadPasswordWarning)
            {
                LogCryptoProPinDiagnostics(hWnd, "Неверный пароль в окне — OK не нажимаем, не тратим попытки");
                if (editHandle != IntPtr.Zero && !string.IsNullOrEmpty(password))
                {
                    ClearEditField(editHandle);
                    TryFillPinField(hWnd, editHandle, password, out _, out int lenAfterBad);
                    EnsureChecked(saveAppHandle);
                    EnsureChecked(saveSystemHandle);
                    return (lenAfterBad >= password.Length, lenAfterBad);
                }
                return (false, 0);
            }

            if (editHandle == IntPtr.Zero || string.IsNullOrEmpty(password))
            {
                EnsureChecked(saveAppHandle);
                EnsureChecked(saveSystemHandle);
                return (false, 0);
            }

            ClearEditField(editHandle);
            await Task.Delay(50);

            TryFillPinField(hWnd, editHandle, password, out var inputMethod, out var textLen);

            int lastErr = Marshal.GetLastWin32Error();
            LogCryptoProPinDiagnostics(hWnd, "password input result",
                method: inputMethod,
                textLenAfter: textLen,
                expectedLen: password.Length,
                lastError: lastErr);

            await Task.Delay(100);
            EnsureChecked(saveAppHandle);
            EnsureChecked(saveSystemHandle);
            await Task.Delay(200);

            if (!hasBadPasswordWarning && okHandle != IntPtr.Zero)
            {
                var sendClick = SendMessage(okHandle, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                LogCryptoProPinDiagnostics(hWnd, "OK clicked", bmClickResult: sendClick.ToInt64(), lastError: Marshal.GetLastWin32Error());
            }

            await Task.Delay(500);
            textLen = SendMessage(editHandle, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero).ToInt32();
            return (textLen >= password.Length, textLen);
        }
        catch (Exception ex)
        {
            LogCryptoProPinDiagnostics(hWnd, "HandleCryptoProAuthWindow error", error: ex.Message);
            return (false, 0);
        }
    }

    private static void ClearEditField(IntPtr editHandle)
    {
        const int EM_SETSEL = 0x00B1;
        const int EM_REPLACESEL = 0x00C2;
        SendMessage(editHandle, EM_SETSEL, IntPtr.Zero, new IntPtr(-1));
        SendMessage(editHandle, EM_REPLACESEL, IntPtr.Zero, "");
    }

    /// <summary>Пробует заполнить поле PIN: WM_SETTEXT → UIA ValuePattern → SendInput. Возвращает метод и длину текста после.</summary>
    private void TryFillPinField(IntPtr hWnd, IntPtr editHandle, string password, out string method, out int textLen)
    {
        const int WM_SETTEXT = 0x000C;
        const int WM_GETTEXTLENGTH = 0x000E;

        textLen = 0;
        method = "none";

        SendMessage(editHandle, WM_SETTEXT, IntPtr.Zero, password);
        Thread.Sleep(150);
        textLen = SendMessage(editHandle, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero).ToInt32();
        if (textLen >= password.Length)
        {
            method = "WM_SETTEXT";
            return;
        }

        try
        {
            var el = AutomationElement.FromHandle(editHandle);
            if (el != null)
            {
                var valuePattern = el.GetCurrentPattern(ValuePattern.Pattern) as ValuePattern;
                if (valuePattern != null)
                {
                    valuePattern.SetValue(password);
                    Thread.Sleep(150);
                    textLen = SendMessage(editHandle, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero).ToInt32();
                    if (textLen >= password.Length)
                    {
                        method = "UIAutomation_ValuePattern";
                        return;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LogCryptoProPinDiagnostics(hWnd, "UIA fallback failed", error: ex.Message);
        }

        ClearEditField(editHandle);
        Thread.Sleep(50);
        var foreThread = GetWindowThreadProcessId(hWnd, out _);
        var curThread = GetCurrentThreadId();
        bool attached = foreThread != curThread && AttachThreadInput(curThread, foreThread, true);
        try
        {
            SetForegroundWindow(hWnd);
            Thread.Sleep(200);
            SetFocus(editHandle);
            Thread.Sleep(200);
            TypePasswordBySendInput(password);
            Thread.Sleep(200);
        }
        finally
        {
            if (attached)
                AttachThreadInput(curThread, foreThread, false);
        }
        textLen = SendMessage(editHandle, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero).ToInt32();
        method = "SendInput";
    }

    private void LogCryptoProPinDiagnostics(IntPtr hWnd, string message,
        bool? editFound = null, bool? saveApp = null, bool? saveSystem = null, bool? ok = null, bool? badWarning = null,
        string? method = null, int? textLenAfter = null, int? expectedLen = null, int? lastError = null, long? bmClickResult = null, string? error = null)
    {
        try
        {
            string ourIntegrity = GetProcessIntegrityLevelString(Process.GetCurrentProcess().Id);
            uint winPid = 0;
            GetWindowThreadProcessId(hWnd, out winPid);
            string winIntegrity = winPid != 0 ? GetProcessIntegrityLevelString((int)winPid) : "n/a";
            var sb = new StringBuilder();
            sb.Append($"[CryptoPro PIN] {message}");
            sb.Append($" | ourIL={ourIntegrity} winIL={winIntegrity}");
            if (editFound.HasValue) sb.Append($" edit={editFound.Value}");
            if (saveApp.HasValue) sb.Append($" saveApp={saveApp.Value}");
            if (saveSystem.HasValue) sb.Append($" saveSystem={saveSystem.Value}");
            if (ok.HasValue) sb.Append($" ok={ok.Value}");
            if (badWarning.HasValue) sb.Append($" badWarning={badWarning.Value}");
            if (method != null) sb.Append($" method={method}");
            if (textLenAfter.HasValue) sb.Append($" textLen={textLenAfter.Value}");
            if (expectedLen.HasValue) sb.Append($" expectedLen={expectedLen.Value}");
            if (lastError.HasValue) sb.Append($" lastErr={lastError.Value}");
            if (bmClickResult.HasValue) sb.Append($" BM_CLICK={bmClickResult.Value}");
            if (error != null) sb.Append($" error={error}");
            _logger.Info(sb.ToString());
            var editStr = editFound.HasValue ? editFound.Value.ToString().ToLowerInvariant() : "null";
            var methodStr = method != null ? "\"" + EscapeJson(method) + "\"" : "null";
            var textLenStr = textLenAfter.HasValue ? textLenAfter.Value.ToString() : "null";
            var expectedStr = expectedLen.HasValue ? expectedLen.Value.ToString() : "null";
            var lastErrStr = lastError.HasValue ? lastError.Value.ToString() : "null";
            var payload = $"{{\"sessionId\":\"2583df\",\"runId\":\"pinWatcher\",\"location\":\"InstallService.HandleCryptoProAuthWindow\",\"message\":\"{EscapeJson(message)}\",\"ourIntegrity\":\"{EscapeJson(ourIntegrity)}\",\"winIntegrity\":\"{EscapeJson(winIntegrity)}\",\"edit\":{editStr},\"method\":{methodStr},\"textLenAfter\":{textLenStr},\"expectedLen\":{expectedStr},\"lastError\":{lastErrStr},\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}";
            File.AppendAllText("debug-2583df.log", payload + "\n");
        }
        catch { }

        static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }
    }

    private static string GetProcessIntegrityLevelString(int processId)
    {
        const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const int TokenIntegrityLevel = 25;
        const int SECURITY_MANDATORY_LOW_RID = 0x1000;
        const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
        const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

        try
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (hProcess == IntPtr.Zero)
                return "open_fail_" + Marshal.GetLastWin32Error();
            try
            {
                if (!OpenProcessToken(hProcess, 0x0008 /*TOKEN_QUERY*/, out IntPtr hToken))
                    return "token_fail_" + Marshal.GetLastWin32Error();
                try
                {
                    int size = 0;
                    GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out size);
                    if (size <= 0)
                        return "size_fail";
                    IntPtr buf = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf, size, out size))
                            return "get_fail_" + Marshal.GetLastWin32Error();
                        var sid = Marshal.ReadIntPtr(buf);
                        int subAuthCount = Marshal.ReadByte(sid, 1);
                        if (subAuthCount < 1)
                            return "?";
                        int rid = Marshal.ReadInt32(sid, 8 + 4 * (subAuthCount - 1));
                        if (rid < SECURITY_MANDATORY_LOW_RID) return "Untrusted";
                        if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "Low";
                        if (rid < SECURITY_MANDATORY_HIGH_RID) return "Medium";
                        if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "High";
                        return "System";
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buf);
                    }
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        catch (Exception ex)
        {
            return "ex_" + ex.Message;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  WinAPI P/Invoke declarations
    // ──────────────────────────────────────────────────────────────

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetFocus(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    private const int INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public int type;
        public INPUTUNION u;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    private static extern IntPtr GetMessageExtraInfo();

    private const int WM_SETTEXT = 0x000C;
    private const int WM_LBUTTONDOWN = 0x0201;
    private const int WM_LBUTTONUP   = 0x0202;
    private const int MK_LBUTTON     = 0x0001;
    private const int BM_CLICK = 0x00F5;
    private const int BM_GETCHECK = 0x00F0;
    private const int BM_SETCHECK = 0x00F1;
    private const int BST_CHECKED = 0x0001;
    private const int GWL_STYLE = -16;
    private const int ES_PASSWORD = 0x0020;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    private static string GetWindowTextSafe(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        var len = GetWindowText(hWnd, sb, sb.Capacity);
        return len > 0 ? sb.ToString() : string.Empty;
    }

    private static string GetClassNameSafe(IntPtr hWnd)
    {
        var sb = new StringBuilder(64);
        var len = GetClassName(hWnd, sb, sb.Capacity);
        return len > 0 ? sb.ToString() : string.Empty;
    }

    private static void EnsureChecked(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return;
        var state = SendMessage(hWnd, BM_GETCHECK, IntPtr.Zero, IntPtr.Zero).ToInt32();
        if (state != BST_CHECKED)
        {
            SendMessage(hWnd, BM_SETCHECK, new IntPtr(BST_CHECKED), IntPtr.Zero);
        }
    }

    /// <summary>Ввод пароля посимвольно через SendInput (как ручной ввод) — fallback для полей, игнорирующих WM_CHAR.</summary>
    private static void TypePasswordBySendInput(string password)
    {
        if (string.IsNullOrEmpty(password)) return;
        var extra = GetMessageExtraInfo();
        foreach (var c in password)
        {
            var inputs = new INPUT[]
            {
                new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = KEYEVENTF_UNICODE, time = 0, dwExtraInfo = extra } } },
                new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } }
            };
            SendInput(2, inputs, Marshal.SizeOf<INPUT>());
            Thread.Sleep(80);
        }
    }

    /// <summary>Отправить Ctrl+A (выделить всё в поле ввода) через SendInput.</summary>
    private static void SendSelectAll()
    {
        const ushort VK_CONTROL = 0x11;
        const ushort VK_A = 0x41;
        var extra = GetMessageExtraInfo();
        var inputs = new INPUT[]
        {
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_CONTROL, wScan = 0, dwFlags = 0, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_A, wScan = 0, dwFlags = 0, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_A, wScan = 0, dwFlags = KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_CONTROL, wScan = 0, dwFlags = KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } }
        };
        SendInput(4, inputs, Marshal.SizeOf<INPUT>());
    }

    /// <summary>Отправить клавишу Delete через SendInput.</summary>
    private static void SendDeleteKey()
    {
        const ushort VK_DELETE = 0x2E;
        var extra = GetMessageExtraInfo();
        var inputs = new INPUT[]
        {
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_DELETE, wScan = 0, dwFlags = 0, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_DELETE, wScan = 0, dwFlags = KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } }
        };
        SendInput(2, inputs, Marshal.SizeOf<INPUT>());
    }

    /// <summary>Отправить Ctrl+V (вставка из буфера) через SendInput.</summary>
    private static void SendPaste()
    {
        const ushort VK_CONTROL = 0x11;
        const ushort VK_V = 0x56;
        var extra = GetMessageExtraInfo();
        var inputs = new INPUT[]
        {
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_CONTROL, wScan = 0, dwFlags = 0, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_V, wScan = 0, dwFlags = 0, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_V, wScan = 0, dwFlags = KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } },
            new INPUT { type = INPUT_KEYBOARD, u = new INPUTUNION { ki = new KEYBDINPUT { wVk = VK_CONTROL, wScan = 0, dwFlags = KEYEVENTF_KEYUP, time = 0, dwExtraInfo = extra } } }
        };
        SendInput(4, inputs, Marshal.SizeOf<INPUT>());
    }

    // ──────────────────────────────────────────────────────────────
    //  File and process helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Copies all files from <paramref name="sourceDir"/> into <paramref name="destDir"/>
    /// (flat, no recursion). Strips ReadOnly attribute on each destination file.
    /// </summary>
    private static void CopyContainerFiles(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir))
        {
            var dest = Path.Combine(destDir, Path.GetFileName(file));
            File.Copy(file, dest, overwrite: true);
            File.SetAttributes(dest, FileAttributes.Normal);
        }
    }

    /// <summary>
    /// Runs <paramref name="exe"/> with <paramref name="args"/> and returns the exit code.
    /// Output is logged at Info level. Process is killed if it exceeds
    /// <paramref name="timeoutMs"/> (default 10 s); returns -1 on timeout.
    /// </summary>
    private async Task<int> RunProcessGetCodeAsync(
        string exe, string args, int timeoutMs = 10_000)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute        = false,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow         = true,
        };
        psi.EnvironmentVariables["CRYPT_SILENT"]         = "1";
        psi.EnvironmentVariables["CRYPT_SUPPRESS_MODAL"] = "1";
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Не удалось запустить: {exe}");

        var outTask = proc.StandardOutput.ReadToEndAsync();
        var errTask = proc.StandardError.ReadToEndAsync();
        var finished = await Task.Run(() => proc.WaitForExit(timeoutMs));

        if (!finished)
        {
            try { proc.Kill(); } catch { }
            _logger.Warn($"Process timeout ({timeoutMs} ms): {Path.GetFileName(exe)}");
            return -1;
        }

        var output = (await outTask) + (await errTask);
        if (!string.IsNullOrWhiteSpace(output))
            _logger.Info($"{Path.GetFileName(exe)}: {output.Trim()}");
        return proc.ExitCode;
    }

    /// <summary>Runs an arbitrary system executable and captures stdout + stderr.</summary>
    private static async Task<(int ExitCode, string Output)> RunSystemCommandAsync(
        string exe, string arguments)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute  = false,
            CreateNoWindow   = true
        };
        psi.EnvironmentVariables["CRYPT_SILENT"]         = "1";
        psi.EnvironmentVariables["CRYPT_SUPPRESS_MODAL"] = "1";
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Не удалось запустить: {exe}");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode,
            string.Join(Environment.NewLine,
                new[] { stdout, stderr }.Where(x => !string.IsNullOrWhiteSpace(x))));
    }

    /// <summary>
    /// Runs certutil -repairstore. CRYPT_SILENT/CRYPT_SUPPRESS_MODAL заданы, чтобы окно
    /// «Аутентификация - КриптоПро CSP» не вылетало (пароль уже передан через certmgr).
    /// Если КриптоПро вернёт NTE_BAD_FLAGS — привязка ключа не выполнится, но окно не появится.
    /// Наследуем окружение процесса и добавляем CRYPT_*, чтобы certutil находил PATH и CSP не показывал диалог.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunRepairStoreCommandAsync(
        string exe, string arguments, int timeoutMs)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute  = false,
            CreateNoWindow   = true
        };
        // Наследуем окружение (в .NET 5+ по умолчанию EnvironmentVariables пустой).
        foreach (var kv in Environment.GetEnvironmentVariables().Cast<DictionaryEntry>())
        {
            var k = kv.Key?.ToString();
            var v = kv.Value?.ToString();
            if (!string.IsNullOrEmpty(k)) psi.EnvironmentVariables[k] = v ?? "";
        }
        psi.EnvironmentVariables["CRYPT_SILENT"]         = "1";
        psi.EnvironmentVariables["CRYPT_SUPPRESS_MODAL"] = "1";
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Не удалось запустить: {exe}");
        var outTask = process.StandardOutput.ReadToEndAsync();
        var errTask = process.StandardError.ReadToEndAsync();
        var finished = await Task.Run(() => process.WaitForExit(timeoutMs));
        if (!finished)
        {
            try { process.Kill(); } catch { }
            _logger.Warn($"certutil -repairstore таймаут {timeoutMs} мс.");
            return (-1, "");
        }
        var stdout = await outTask;
        var stderr = await errTask;
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
            _logger.Info($"Удален старый сертификат: Subject={old.Subject}; Serial={old.SerialNumber}.");
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