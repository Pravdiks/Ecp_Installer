using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EcpInstaller.App.Helpers;

public static class CertificateIdentityMatcher
{
    public static bool IsSameOwner(X509Certificate2 candidate, X509Certificate2 incoming)
    {
        if (string.Equals(candidate.Issuer, incoming.Issuer, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(candidate.SerialNumber, incoming.SerialNumber, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var candidateCn = ExtractCn(candidate.Subject);
        var incomingCn = ExtractCn(incoming.Subject);
        if (!string.IsNullOrWhiteSpace(candidateCn) &&
            string.Equals(candidateCn, incomingCn, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var candidateInn = ExtractValue(candidate.Subject, "INN");
        var incomingInn = ExtractValue(incoming.Subject, "INN");
        if (!string.IsNullOrWhiteSpace(candidateInn) && candidateInn == incomingInn)
        {
            return true;
        }

        var candidateOgrn = ExtractValue(candidate.Subject, "OGRN");
        var incomingOgrn = ExtractValue(incoming.Subject, "OGRN");
        return !string.IsNullOrWhiteSpace(candidateOgrn) && candidateOgrn == incomingOgrn;
    }

    private static string ExtractCn(string subject) => ExtractValue(subject, "CN");

    private static string ExtractValue(string source, string key)
    {
        var match = Regex.Match(source, $@"{key}\s*=\s*([^,]+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
    }
}
