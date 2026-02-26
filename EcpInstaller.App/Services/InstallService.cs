using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using System.Security.Cryptography.X509Certificates;

namespace EcpInstaller.App.Services;

public sealed class InstallService
{
    private readonly AppLogger _logger;
    private readonly InstallerService _installerService;

    public InstallService(AppLogger logger, InstallerService installerService)
    {
        _logger = logger;
        _installerService = installerService;
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
                    await InstallCryptoProAsync(task, password, containerLocation, containerFolder);
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

    private async Task InstallCryptoProAsync(SignatureTask task, string password, ContainerLocation containerLocation, string containerFolder)
    {
        if (string.IsNullOrWhiteSpace(task.ContainerPath) || !Directory.Exists(task.ContainerPath))
            throw new InvalidOperationException("Невозможно установить закрытый ключ: CER не содержит private key (контейнер *.000/*.001 не найден).");

        await _installerService.InstallContainerAndBindCertAsync(task.ContainerPath, task.CertificatePath, containerLocation, containerFolder, password);

        var thumbprint = GetCertThumbprint(task.CertificatePath);
        task.HasPrivateKey = CheckPrivateKeyLinked(thumbprint);
        if (!task.HasPrivateKey.Value)
            _logger.Warn($"Ключ не привязан для {task.DisplayName}!");
    }

    private static string GetCertThumbprint(string cerPath)
    {
        using var cert = new X509Certificate2(cerPath);
        return cert.Thumbprint;
    }

    private static bool CheckPrivateKeyLinked(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                return cert.HasPrivateKey;
        }

        return false;
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
            throw new InvalidOperationException("LocalMachine поддерживается только на Windows.");

        if (storeLocation == StoreLocation.LocalMachine && !WindowsPrincipalHelper.IsAdministrator())
            throw new OperationCanceledException("Для LocalMachine нужны права администратора. Выберите CurrentUser для установки без админа.");
    }
}
