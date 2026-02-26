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

    public async Task InstallContainerAndBindCertAsync(string containerFolder, string cerPath, string? password = null, CancellationToken ct = default)
    {
        if (!Directory.Exists(containerFolder))
            throw new DirectoryNotFoundException($"Папка контейнера не найдена: {containerFolder}");
        if (!File.Exists(cerPath))
            throw new FileNotFoundException("Файл сертификата не найден", cerPath);

        var localHdimageRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Crypto Pro");
        Directory.CreateDirectory(localHdimageRoot);

        var srcName = Path.GetFileName(containerFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var targetName = EnsureUniqueFolderName(localHdimageRoot, srcName);
        var targetPath = Path.Combine(localHdimageRoot, targetName);

        CopyContainer(containerFolder, targetPath);
        _logger.Info($"Контейнер скопирован: {containerFolder} -> {targetPath}");

        var fqcns = await _cli.EnumerateContainerFqcnAsync(ct);
        var fqcn = SelectFqcn(fqcns, targetName);
        if (fqcn is null)
            throw new InvalidOperationException($"Не найден канонический контейнер после копирования: {targetName}. Проверьте csptest -enum_cont output.");

        var certmgr = _cli.FindCertmgrPath();
        var instToCont = await _cli.ResolveInstallToContArgAsync(ct);

        var pinArg = string.IsNullOrWhiteSpace(password) ? string.Empty : $" -pin \"{password}\"";
        var args = $"-install -cont \"{fqcn}\" -file \"{cerPath}\" {instToCont} -silent{pinArg}";

        var result = await _cli.RunProcessAsync(certmgr, args, secretsToMask: password is null ? null : [password], cancellationToken: ct);
        _logger.Info($"certmgr install result: exit={result.ExitCode}; output:\n{result.Output}");
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"certmgr -install завершился с кодом {result.ExitCode}.\n{result.Output}");

        await VerifyInstallAsync(cerPath, password, ct);
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

    private static void CopyContainer(string sourceFolder, string destinationFolder)
    {
        if (Directory.Exists(destinationFolder))
            Directory.Delete(destinationFolder, true);

        Directory.CreateDirectory(destinationFolder);
        foreach (var file in Directory.GetFiles(sourceFolder))
        {
            File.Copy(file, Path.Combine(destinationFolder, Path.GetFileName(file)), overwrite: true);
        }
    }

    private static string EnsureUniqueFolderName(string root, string baseName)
    {
        var candidate = baseName;
        var index = 1;
        while (Directory.Exists(Path.Combine(root, candidate)))
        {
            candidate = $"{baseName}_{index++}";
        }

        return candidate;
    }

    private static string? SelectFqcn(IEnumerable<string> fqcns, string targetFolderName)
    {
        var normalized = targetFolderName.ToLowerInvariant();
        return fqcns.FirstOrDefault(x =>
            x.Contains($"\\HDIMAGE\\{normalized}", StringComparison.OrdinalIgnoreCase)
            || x.EndsWith($"\\{targetFolderName}", StringComparison.OrdinalIgnoreCase)
            || Regex.IsMatch(x, $@"\\{Regex.Escape(targetFolderName)}(\b|$)", RegexOptions.IgnoreCase));
    }
}
