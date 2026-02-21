namespace EcpInstaller.App.Models;

public sealed class AppSettings
{
    public string Password { get; set; } = "123456";
    public ContainerLocation ContainerLocation { get; set; } = ContainerLocation.Disk;
    public string ContainerFolder { get; set; } = @"D:\EcpInstallerContainers";
    public bool TopMost { get; set; } = true;
    public string StoreLocationTag { get; set; } = "CurrentUser";
    public bool OnlyMostActualCertificate { get; set; } = true;
}
