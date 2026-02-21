using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EcpInstaller.App.Models;

public sealed class SignatureTask : INotifyPropertyChanged
{
    private SignatureTaskStatus _status = SignatureTaskStatus.Pending;
    private string _message = "Ожидает установки";

    public SignatureSourceKind Kind { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string CertificatePath { get; init; } = string.Empty;

    public string? ContainerPath { get; init; }

    public SignatureTaskStatus Status
    {
        get => _status;
        set
        {
            _status = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusLabel));
        }
    }


    public string StatusLabel => Status switch
    {
        SignatureTaskStatus.Pending => "Ожидает установки",
        SignatureTaskStatus.Running => "Установка...",
        SignatureTaskStatus.Success => "Установлено",
        SignatureTaskStatus.Error => "Ошибка",
        SignatureTaskStatus.Skipped => "Пропущено",
        _ => Status.ToString()
    };

    public string Message
    {
        get => _message;
        set
        {
            _message = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
