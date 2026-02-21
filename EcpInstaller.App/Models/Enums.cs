namespace EcpInstaller.App.Models;

public enum SignatureTaskStatus
{
    Pending,
    Running,
    Success,
    Error,
    Skipped
}

public enum SignatureSourceKind
{
    Pfx,
    CryptoProContainer
}

public enum ContainerLocation
{
    Disk,
    Registry
}
