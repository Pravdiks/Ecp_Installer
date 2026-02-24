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
            OnPropertyChanged(nameof(GroupKey));
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

    /// <summary>
    /// Computed group key used by the DataGrid GroupStyle to cluster
    /// skipped items under collapsible headers.
    /// </summary>
    public string GroupKey => Status switch
    {
        SignatureTaskStatus.Skipped when Message.Contains("Просрочен", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (просрочены)",
        SignatureTaskStatus.Skipped when Message.Contains("нет ключа", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (нет ключа)",
        SignatureTaskStatus.Skipped when Message.Contains("актуальный", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (есть более актуальный)",
        SignatureTaskStatus.Skipped => "Пропущено",
        _ => "Задачи на установку"
    };

    public string Message
    {
        get => _message;
        set
        {
            _message = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(GroupKey));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
