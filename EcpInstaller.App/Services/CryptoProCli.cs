using System.Diagnostics;
using System.IO;

namespace EcpInstaller.App.Services;

public sealed class CryptoProCli
{
    private static readonly string[] CandidateRoots =
    [
        @"C:\\Program Files\\Crypto Pro\\CSP",
        @"C:\\Program Files (x86)\\Crypto Pro\\CSP"
    ];

    public string? ResolveCertMgrPath()
    {
        foreach (var root in CandidateRoots)
        {
            var candidate = Path.Combine(root, "certmgr.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public async Task<(int ExitCode, string Output)> RunAsync(string exe, string arguments)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Не удалось запустить CryptoPro CLI");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, string.Join(Environment.NewLine, new[] { stdout, stderr }.Where(x => !string.IsNullOrWhiteSpace(x))));
    }
}
