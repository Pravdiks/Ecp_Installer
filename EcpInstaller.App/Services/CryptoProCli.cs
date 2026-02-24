using System.Diagnostics;
using System.IO;

namespace EcpInstaller.App.Services;

public sealed class CryptoProCli
{
    // Search both x64 and x86 installation paths.
    private static readonly string[] CandidateRoots =
    [
        @"C:\Program Files\Crypto Pro\CSP",
        @"C:\Program Files (x86)\Crypto Pro\CSP"
    ];

    /// <summary>Returns the path to certmgr.exe, or null if CryptoPro CSP is not installed.</summary>
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

    /// <summary>
    /// Returns the major version number of the installed CryptoPro CSP
    /// (typically 4 or 5), or 0 if it cannot be determined.
    /// </summary>
    public int ResolveCspVersion()
    {
        var certMgr = ResolveCertMgrPath();
        if (certMgr is null)
        {
            return 0;
        }

        var cspDll = Path.Combine(Path.GetDirectoryName(certMgr)!, "csp.dll");
        if (!File.Exists(cspDll))
        {
            return 0;
        }

        try
        {
            return FileVersionInfo.GetVersionInfo(cspDll).ProductMajorPart;
        }
        catch
        {
            return 0;
        }
    }

    public async Task<(int ExitCode, string Output)> RunAsync(string exe, string arguments)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            // Run from the CryptoPro directory so it can find its own DLLs.
            WorkingDirectory = Path.GetDirectoryName(exe) ?? string.Empty
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Не удалось запустить CryptoPro CLI");
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode,
            string.Join(Environment.NewLine,
                new[] { stdout, stderr }.Where(x => !string.IsNullOrWhiteSpace(x))));
    }
}
