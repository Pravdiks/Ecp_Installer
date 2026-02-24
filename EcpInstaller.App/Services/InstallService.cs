using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace EcpInstaller.App.Services;

public sealed class InstallService
{
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
            task.Message = $"Ошибка установки: {ex.Message}";
            _logger.Error($"Ошибка установки '{task.DisplayName}': {ex}");
        }
    }

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

        // Place container and get the CryptoPro UNC path (\\.\ prefix required by CryptoPro CSP).
        var contUncPath = await PlaceContainerAsync(task.ContainerPath!, containerLocation, containerFolder);

        var locationArg = storeLocation == StoreLocation.CurrentUser ? "uMy" : "mMy";

        // Try GOST-2012 (provtype 80) first; fall back to GOST-2001 (provtype 75) for older keys.
        var (exitCode, output) = await RunCertMgrInstallAsync(certMgr, task.CertificatePath, contUncPath, password, locationArg, provType: 80);

        if (exitCode != 0)
        {
            _logger.Warn($"certmgr -provtype 80 завершился с кодом {exitCode}. Повтор с -provtype 75 (ГОСТ-2001)...");
            (exitCode, output) = await RunCertMgrInstallAsync(certMgr, task.CertificatePath, contUncPath, password, locationArg, provType: 75);
        }

        if (exitCode != 0)
        {
            throw new InvalidOperationException($"certmgr завершился с кодом {exitCode}.\n{output}");
        }

        _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}");
        _logger.Info($"  Контейнер UNC: {contUncPath}");

        var cert = new X509Certificate2(task.CertificatePath);
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, cert);
    }

    /// <summary>
    /// Builds and runs the certmgr -inst command, logging the full command line and output.
    /// </summary>
    private async Task<(int ExitCode, string Output)> RunCertMgrInstallAsync(
        string certMgr, string cerPath, string contUncPath, string password, string locationArg, int provType)
    {
        var args = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType} -pin ""{password}""";

        // Log the command (mask the PIN to avoid leaking passwords into logs).
        var argsForLog = $@"-inst -store {locationArg} -file ""{cerPath}"" -cont ""{contUncPath}"" -provtype {provType} -pin ""***""";
        _logger.Info($"Запуск certmgr: {certMgr} {argsForLog}");

        var result = await _cryptoProCli.RunAsync(certMgr, args);
        _logger.Info($"certmgr завершился с кодом {result.ExitCode}. Вывод:\n{result.Output}");
        return result;
    }

    /// <summary>
    /// Copies the container to its target location and returns the CryptoPro UNC path.
    /// <list type="bullet">
    ///   <item>Disk mode  → copies to <paramref name="containerFolder"/>,
    ///         returns <c>\\.\{full path to copied folder}</c></item>
    ///   <item>Registry mode → copies to <c>%APPDATA%\Crypto Pro\Keys\{name}\</c>,
    ///         returns <c>\\.\REGISTRY\{name}</c></item>
    /// </list>
    /// </summary>
    private async Task<string> PlaceContainerAsync(string sourceContainer, ContainerLocation containerLocation, string containerFolder)
    {
        var containerName = Path.GetFileName(
            sourceContainer.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (containerLocation == ContainerLocation.Registry)
        {
            // CryptoPro registry provider reads user containers from %APPDATA%\Crypto Pro\Keys\{name}\
            var keysRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Crypto Pro", "Keys");
            var destination = Path.Combine(keysRoot, containerName);

            _logger.Info($"Режим реестра: копирование контейнера в {destination}");
            Directory.CreateDirectory(keysRoot);

            if (Directory.Exists(destination))
            {
                Directory.Delete(destination, true);
            }

            await Task.Run(() => CopyDirectory(sourceContainer, destination));
            _logger.Info($"Контейнер скопирован: {destination}");

            // UNC path for registry-stored containers.
            var regUncPath = $@"\\.\REGISTRY\{containerName}";
            _logger.Info($"UNC-путь контейнера (реестр): {regUncPath}");
            return regUncPath;
        }

        // Disk mode: copy to the user-specified folder.
        Directory.CreateDirectory(containerFolder);
        var diskDestination = Path.Combine(containerFolder, containerName);

        var sourceFullPath = Path.GetFullPath(sourceContainer)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var destinationFullPath = Path.GetFullPath(diskDestination)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!string.Equals(sourceFullPath, destinationFullPath, StringComparison.OrdinalIgnoreCase))
        {
            if (Directory.Exists(diskDestination))
            {
                Directory.Delete(diskDestination, true);
            }

            await Task.Run(() => CopyDirectory(sourceContainer, diskDestination));
            _logger.Info($"Контейнер скопирован на диск: {diskDestination}");
        }
        else
        {
            _logger.Info($"Контейнер уже находится в целевой папке: {destinationFullPath}");
        }

        // CryptoPro requires a UNC path even for disk containers: \\.\{full path}
        // Example: \\.\D:\EcpInstallerContainers\queriejw.001
        var diskUncPath = $@"\\.\{destinationFullPath}";
        _logger.Info($"UNC-путь контейнера (диск): {diskUncPath}");
        return diskUncPath;
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true);
        }

        foreach (var dir in Directory.EnumerateDirectories(source))
        {
            CopyDirectory(dir, Path.Combine(destination, Path.GetFileName(dir)));
        }
    }

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
