namespace EcpInstaller.App.Models;

public sealed class AppSettings
{
    public ContainerLocation ContainerLocation { get; set; } = ContainerLocation.Disk;
    public string ContainerFolder { get; set; } = @"D:\EcpInstallerContainers";
    public bool TopMost { get; set; } = true;
    public string StoreLocationTag { get; set; } = "CurrentUser";
    public bool OnlyMostActualCertificate { get; set; } = true;
    /// <summary>Пароль контейнера/PFX (сохраняется по запросу пользователя для удобства тестирования).</summary>
    public string? ContainerPassword { get; set; }
}
