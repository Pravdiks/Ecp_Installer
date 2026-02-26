using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace EcpInstaller.App.Services;

public sealed class CryptoProCliService
{
    private readonly AppLogger _logger;
    private string? _installToContArg;

    public CryptoProCliService(AppLogger logger) => _logger = logger;

    public string FindCertmgrPath() => FindToolPath("certmgr.exe")
        ?? throw new FileNotFoundException("certmgr.exe не найден. Установите CryptoPro CSP 4/5.");

    public string FindCsptestPath() => FindToolPath("csptest.exe")
        ?? throw new FileNotFoundException("csptest.exe не найден. Установите CryptoPro CSP 4/5.");

    public async Task<string> ResolveInstallToContArgAsync(CancellationToken ct = default)
    {
        if (!string.IsNullOrEmpty(_installToContArg))
            return _installToContArg;

        var certmgr = FindCertmgrPath();
        var result = await RunProcessAsync(certmgr, "-?", timeoutMs: 15000, cancellationToken: ct);
        var help = result.Output;

        var candidates = new[] { "-inst-to-cont", "-insttocont", "inst-to-cont", "insttocont" };
        foreach (var candidate in candidates)
        {
            if (help.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                _installToContArg = candidate.StartsWith('-') ? candidate : $"-{candidate}";
                _logger.Info($"Определён аргумент certmgr для привязки: {_installToContArg}");
                return _installToContArg;
            }
        }

        _installToContArg = "-inst-to-cont";
        _logger.Warn("Не удалось определить ключ привязки по certmgr -?. Используется fallback: -inst-to-cont");
        return _installToContArg;
    }

    public async Task<ProcessResult> RunProcessAsync(
        string exe,
        string args,
        int timeoutMs = 60000,
        IEnumerable<string>? secretsToMask = null,
        CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.CurrentDirectory,
        };

        psi.EnvironmentVariables["CRYPT_SUPPRESS_MODAL"] = "1";
        psi.EnvironmentVariables["CRYPT_SILENT"] = "1";

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Не удалось запустить процесс: {exe}");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Таймаут выполнения: {Path.GetFileName(exe)} {Mask(args, secretsToMask)} ({timeoutMs} ms)");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var output = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(stdout)) output.AppendLine(stdout.Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) output.AppendLine(stderr.Trim());

        return new ProcessResult(process.ExitCode, Mask(output.ToString().Trim(), secretsToMask));
    }

    public async Task<string[]> EnumerateContainerFqcnAsync(CancellationToken ct = default)
    {
        var csptest = FindCsptestPath();
        var res = await RunProcessAsync(csptest, "-keyset -enum_cont -verifyc -fq", cancellationToken: ct);
        if (res.ExitCode != 0)
            _logger.Warn($"csptest enum_cont завершился с кодом {res.ExitCode}");

        var lines = res.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        const string pattern = @"\\\\\.\\(HDIMAGE|REGISTRY)\\[^\s""']+";
        var matches = lines
            .SelectMany(l => Regex.Matches(l, pattern, RegexOptions.IgnoreCase).Cast<Match>())
            .Select(m => m.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return matches;
    }

    private static string Mask(string text, IEnumerable<string>? secrets)
    {
        if (string.IsNullOrEmpty(text) || secrets is null)
            return text;

        var result = text;
        foreach (var secret in secrets.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct())
            result = result.Replace(secret, "****", StringComparison.Ordinal);

        return result;
    }

    private static string? FindToolPath(string fileName)
    {
        var directCandidates = new[]
        {
            @"C:\Program Files\Crypto Pro\CSP",
            @"C:\Program Files (x86)\Crypto Pro\CSP",
            @"C:\Program Files\CryptoPro\CSP",
            @"C:\Program Files (x86)\CryptoPro\CSP",
        }
        .Select(root => Path.Combine(root, fileName))
        .Where(File.Exists)
        .ToList();

        if (directCandidates.Count > 0)
            return directCandidates[0];

        foreach (var regPath in new[] { @"SOFTWARE\Crypto Pro\CSP", @"SOFTWARE\WOW6432Node\Crypto Pro\CSP" })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                var dir = key?.GetValue("InstallPath") as string;
                if (string.IsNullOrWhiteSpace(dir))
                    continue;

                var candidate = Path.Combine(dir, fileName);
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // ignore
            }
        }

        return null;
    }
}

public readonly record struct ProcessResult(int ExitCode, string Output);
