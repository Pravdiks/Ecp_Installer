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

        var targetContainer = await PlaceContainerAsync(task.ContainerPath!, containerLocation, containerFolder);
        var cert = new X509Certificate2(task.CertificatePath);

        var locationArg = storeLocation == StoreLocation.CurrentUser ? "uMy" : "mMy";
        var args = $@"-inst -store {locationArg} -file ""{task.CertificatePath}"" -cont ""{targetContainer}"" -pin ""{password}""";
        var result = await _cryptoProCli.RunAsync(certMgr, args);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"CryptoPro certmgr завершился с кодом {result.ExitCode}. {result.Output}");
        }

        _logger.Info($"CryptoPro сертификат установлен: {task.CertificatePath}, контейнер: {targetContainer}");

        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, cert);
    }

    private async Task<string> PlaceContainerAsync(string sourceContainer, ContainerLocation containerLocation, string containerFolder)
    {
        if (containerLocation == ContainerLocation.Registry)
        {
            _logger.Info("Выбрано хранение контейнера в реестре CurrentUser.");
            return sourceContainer;
        }

        Directory.CreateDirectory(containerFolder);
        var destination = Path.Combine(containerFolder, Path.GetFileName(sourceContainer));

        var sourceFullPath = Path.GetFullPath(sourceContainer)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var destinationFullPath = Path.GetFullPath(destination)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (string.Equals(sourceFullPath, destinationFullPath, StringComparison.OrdinalIgnoreCase))
        {
            _logger.Info($"Контейнер уже находится в целевой папке: {destinationFullPath}");
            return sourceContainer;
        }

        if (Directory.Exists(destination))
        {
            Directory.Delete(destination, true);
        }

        await Task.Run(() => CopyDirectory(sourceContainer, destination));
        _logger.Info($"Контейнер скопирован на диск: {destination}");
        return destination;
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
