using EcpInstaller.App.Helpers;
using EcpInstaller.App.Models;
using Microsoft.Win32;
using System.Diagnostics;
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

    private async Task InstallCryptoProAsync(
        SignatureTask task, string password,
        StoreLocation storeLocation,
        ContainerLocation containerLocation,
        string containerFolder)
    {
        EnsureAccess(storeLocation);

        if (string.IsNullOrWhiteSpace(task.ContainerPath) || !Directory.Exists(task.ContainerPath))
            throw new InvalidOperationException("Для CER не найден контейнер закрытого ключа рядом с сертификатом.");

        string certmgrPath = FindCertmgr();
        string storeName = storeLocation == StoreLocation.LocalMachine ? "My" : "uMy";

        // Всегда копируем контейнер в реестр: HDIMAGE игнорирует -pin.
        string contPath = await CopyContainerToRegistry(task.ContainerPath);
        await Task.Delay(1000);

        // В режиме Disk дополнительно храним копию в выбранной папке,
        // но установка всё равно выполняется из реестрового контейнера.
        if (containerLocation == ContainerLocation.Disk)
        {
            try
            {
                string actualFolder = EnsureContainerFolder(containerFolder);
                string diskDest = Path.Combine(actualFolder, Path.GetFileName(task.ContainerPath));
                if (!Directory.Exists(diskDest))
                {
                    Directory.CreateDirectory(diskDest);
                    foreach (var f in Directory.GetFiles(task.ContainerPath, "*.key"))
                        File.Copy(f, Path.Combine(diskDest, Path.GetFileName(f)), true);
                    _logger.Info($"Контейнер скопирован на диск: {diskDest}");
                }
            }
            catch (Exception ex)
            {
                _logger.Warn($"Не удалось скопировать на диск: {ex.Message}");
            }
        }

        var (cspMajor, _) = GetCryptoproVersion(certmgrPath);
        int[] provTypes = cspMajor >= 5 ? [80, 75, 81] : [80, 75];

        Exception? lastEx = null;
        bool installed = false;

        foreach (int provType in provTypes)
        {
            string args = $"-inst -store {storeName} " +
                          $"-file \"{task.CertificatePath}\" " +
                          $"-cont \"{contPath}\" " +
                          $"-provtype {provType} " +
                          $"-pin \"{password}\" " +
                          "-silent";

            _logger.Info($"certmgr: {args.Replace(password, "***")}");

            var psi = new ProcessStartInfo(certmgrPath, args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.EnvironmentVariables["CRYPT_SUPPRESS_MODAL"] = "1";

            using var proc = Process.Start(psi)!;
            string output = await proc.StandardOutput.ReadToEndAsync();
            output += await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            _logger.Info($"certmgr exitCode={proc.ExitCode}. Output:\n{output}");

            if (proc.ExitCode == 0)
            {
                installed = true;
                _logger.Info($"Установлено с provtype={provType}");
                break;
            }

            lastEx = new InvalidOperationException($"certmgr код {proc.ExitCode}\n{output}");
        }

        if (!installed)
            throw lastEx ?? new InvalidOperationException("Не удалось установить сертификат через certmgr.");

        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        RemoveOldCertificatesExcept(store, new X509Certificate2(task.CertificatePath));

        await Task.Delay(500);
        string thumbprint = GetCertThumbprint(task.CertificatePath);
        bool hasKey = CheckPrivateKeyLinked(thumbprint, storeLocation);
        _logger.Info($"HasPrivateKey={hasKey}, Thumbprint={thumbprint}");

        if (!hasKey)
        {
            _logger.Info("Попытка repairstore...");
            string userArg = storeLocation == StoreLocation.CurrentUser ? "-user " : string.Empty;
            await RunProcess("certutil.exe", $"-repairstore {userArg}My \"{thumbprint}\"");
            await Task.Delay(300);
            hasKey = CheckPrivateKeyLinked(thumbprint, storeLocation);
            _logger.Info($"HasPrivateKey после repairstore={hasKey}");
        }

        task.HasPrivateKey = hasKey;
        if (!hasKey)
            _logger.Warn($"Ключ не привязан для {task.DisplayName}!");
    }

    private Task<string> CopyContainerToRegistry(string sourceContainerPath)
    {
        string keysFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Crypto Pro", "Keys");
        Directory.CreateDirectory(keysFolder);

        string rawName = Path.GetFileName(sourceContainerPath);
        string regName = Path.GetFileNameWithoutExtension(rawName);

        string destFolder = Path.Combine(keysFolder, regName);

        if (Directory.Exists(destFolder))
            Directory.Delete(destFolder, true);
        Directory.CreateDirectory(destFolder);

        int copied = 0;
        foreach (var file in Directory.GetFiles(sourceContainerPath))
        {
            File.Copy(file, Path.Combine(destFolder, Path.GetFileName(file)), overwrite: true);
            copied++;
        }

        string contPath = $@"\\.\REGISTRY\{regName}";
        _logger.Info($"Контейнер в реестре: {destFolder} ({copied} файлов). Path: {contPath}");

        return Task.FromResult(contPath);
    }

    private string EnsureContainerFolder(string requestedFolder)
    {
        try
        {
            string root = Path.GetPathRoot(requestedFolder) ?? string.Empty;
            if (!string.IsNullOrEmpty(root) && !Directory.Exists(root))
            {
                string fallback = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "EcpInstaller", "Containers");
                Directory.CreateDirectory(fallback);
                _logger.Warn($"Диск недоступен. Fallback: {fallback}");
                return fallback;
            }

            Directory.CreateDirectory(requestedFolder);
            return requestedFolder;
        }
        catch
        {
            string fallback = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "EcpInstaller", "Containers");
            Directory.CreateDirectory(fallback);
            _logger.Warn($"Ошибка папки. Fallback: {fallback}");
            return fallback;
        }
    }

    private static string FindCertmgr()
    {
        string[] paths =
        {
            @"C:\Program Files\Crypto Pro\CSP\certmgr.exe",
            @"C:\Program Files (x86)\Crypto Pro\CSP\certmgr.exe",
            @"C:\Program Files\CryptoPro\CSP\certmgr.exe",
            @"C:\Program Files (x86)\CryptoPro\CSP\certmgr.exe",
        };

        string? found = paths.FirstOrDefault(File.Exists);
        if (found is not null)
            return found;

        foreach (var regPath in new[] { @"SOFTWARE\Crypto Pro\CSP", @"SOFTWARE\WOW6432Node\Crypto Pro\CSP" })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                string? dir = key?.GetValue("InstallPath") as string;
                if (!string.IsNullOrEmpty(dir))
                {
                    string candidate = Path.Combine(dir, "certmgr.exe");
                    if (File.Exists(candidate))
                        return candidate;
                }
            }
            catch
            {
                // ignore registry lookup issues
            }
        }

        throw new FileNotFoundException("certmgr.exe не найден. КриптоПро CSP не установлен?");
    }

    private static (int major, int minor) GetCryptoproVersion(string certmgrPath)
    {
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(certmgrPath);
            return (vi.FileMajorPart, vi.FileMinorPart);
        }
        catch
        {
            return (5, 0);
        }
    }

    private static string GetCertThumbprint(string cerPath)
    {
        using var cert = new X509Certificate2(cerPath);
        return cert.Thumbprint;
    }

    private static bool CheckPrivateKeyLinked(string thumbprint, StoreLocation storeLocation)
    {
        using var store = new X509Store(StoreName.My, storeLocation);
        store.Open(OpenFlags.ReadOnly);
        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                return cert.HasPrivateKey;
        }

        return false;
    }

    private async Task<int> RunProcess(string exe, string args, int timeoutMs = 30000)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi)!;
        var outputTask = proc.StandardOutput.ReadToEndAsync();
        var errorTask = proc.StandardError.ReadToEndAsync();

        bool finished = await Task.Run(() => proc.WaitForExit(timeoutMs));
        if (!finished)
        {
            proc.Kill();
            _logger.Warn($"Process timeout: {exe}");
        }

        string output = await outputTask + await errorTask;
        if (!string.IsNullOrWhiteSpace(output))
            _logger.Info($"{Path.GetFileName(exe)} output: {output}");

        return finished ? proc.ExitCode : -1;
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
