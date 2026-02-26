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

        foreach (var candidate in new[] { "-inst-to-cont", "-insttocont", "inst-to-cont", "insttocont" })
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

    public async Task<ContainerEnumerationResult> EnumerateContainersFqcnAsync(CancellationToken ct = default)
    {
        var csptest = FindCsptestPath();
        var candidateArgs = new[]
        {
            "-keyset -enum_cont -verifyc -fqcn",
            "-keyset -enum_c -verifyc -fqcn",
            "-keys -enum -verifyc -fqcn -unique"
        };

        ProcessResult? picked = null;
        string usedArgs = candidateArgs[0];
        foreach (var args in candidateArgs)
        {
            var result = await RunProcessAsync(csptest, args, cancellationToken: ct);
            if (result.ExitCode == 0 && !string.IsNullOrWhiteSpace(result.Output))
            {
                picked = result;
                usedArgs = args;
                break;
            }

            _logger.Warn($"csptest {args} -> code={result.ExitCode}");
        }

        if (picked is null)
        {
            var fallback = await RunProcessAsync(csptest, candidateArgs[0], cancellationToken: ct);
            picked = fallback;
            usedArgs = candidateArgs[0];
        }

        var output = picked.Value.Output;
        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        const string commonPattern = "(?:\\\\\\.\\)?(?:HDIMAGE|REGISTRY)\\[^\\s\"']+";

        var shortList = new List<string>();
        var uniqueList = new List<string>();

        foreach (var line in lines)
        {
            var parts = line.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                foreach (Match match in Regex.Matches(part, commonPattern, RegexOptions.IgnoreCase))
                {
                    var value = NormalizeFqcn(match.Value);
                    if (value.IndexOf("\\HDIMAGE\\HDIMAGE\\", StringComparison.OrdinalIgnoreCase) >= 0
                        || value.IndexOf("\\REGISTRY\\REGISTRY\\", StringComparison.OrdinalIgnoreCase) >= 0
                        || Regex.IsMatch(value, @"\\[0-9A-F]{4,}$", RegexOptions.IgnoreCase))
                    {
                        uniqueList.Add(value);
                    }
                    else
                    {
                        shortList.Add(value);
                    }
                }
            }
        }

        var shortDistinct = shortList.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var uniqueDistinct = uniqueList.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return new ContainerEnumerationResult(shortDistinct, uniqueDistinct, usedArgs, output);
    }

    private static string NormalizeFqcn(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("\\\\.\\", StringComparison.Ordinal))
            return trimmed;
        if (trimmed.StartsWith("HDIMAGE\\", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("REGISTRY\\", StringComparison.OrdinalIgnoreCase))
        {
            return $"\\\\.\\{trimmed}";
        }

        return trimmed;
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
public readonly record struct ContainerEnumerationResult(string[] ContainersShort, string[] ContainersUnique, string UsedArgs, string RawOutput);
