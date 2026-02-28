namespace EcpInstaller.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        // Suppress CryptoPro PIN dialogs at the process level so all child
        // processes (certmgr, csptest) inherit this setting automatically.
        Environment.SetEnvironmentVariable("CRYPT_SILENT", "1");
        Environment.SetEnvironmentVariable("CRYPT_SUPPRESS_MODAL", "1");
        base.OnStartup(e);
    }
}
