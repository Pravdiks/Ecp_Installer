using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EcpInstaller.App.Models;

public sealed class SignatureTask : INotifyPropertyChanged
{
    private SignatureTaskStatus _status = SignatureTaskStatus.Pending;
    private string _message = "Ожидает установки";
    private bool? _hasPrivateKey;

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
            OnPropertyChanged(nameof(GroupSortOrder));
        }
    }

    /// <summary>
    /// null = not yet checked; true = private key linked; false = no key linked (warning).
    /// </summary>
    public bool? HasPrivateKey
    {
        get => _hasPrivateKey;
        set
        {
            _hasPrivateKey = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusLabel));
        }
    }

    public string StatusLabel => (Status, HasPrivateKey) switch
    {
        (SignatureTaskStatus.Success, false) => "⚠ Ключ не привязан",
        (SignatureTaskStatus.Pending, _)     => "Ожидает установки",
        (SignatureTaskStatus.Running, _)     => "Установка...",
        (SignatureTaskStatus.Success, _)     => "Установлено",
        (SignatureTaskStatus.Error,   _)     => "Ошибка",
        (SignatureTaskStatus.Skipped, _)     => "Пропущено",
        _                                    => Status.ToString()
    };

    /// <summary>
    /// Computed group key for the DataGrid GroupStyle.
    /// Errors get their own group; skipped items are split by reason.
    /// </summary>
    public string GroupKey => Status switch
    {
        SignatureTaskStatus.Error => "Ошибка установки",
        SignatureTaskStatus.Skipped when Message.Contains("Просрочен", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (просрочены)",
        SignatureTaskStatus.Skipped when Message.Contains("нет ключа", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (нет ключа)",
        SignatureTaskStatus.Skipped when Message.Contains("актуальный", StringComparison.OrdinalIgnoreCase)
            => "Пропущено (есть более актуальный)",
        SignatureTaskStatus.Skipped => "Пропущено",
        _ => "Задачи на установку"
    };

    /// <summary>
    /// Numeric sort key so groups appear in the right order:
    /// 1 = install tasks, 2 = errors, 3–6 = skipped sub-groups.
    /// </summary>
    public int GroupSortOrder => Status switch
    {
        SignatureTaskStatus.Error => 2,
        SignatureTaskStatus.Skipped when Message.Contains("Просрочен", StringComparison.OrdinalIgnoreCase)   => 3,
        SignatureTaskStatus.Skipped when Message.Contains("актуальный", StringComparison.OrdinalIgnoreCase) => 4,
        SignatureTaskStatus.Skipped when Message.Contains("нет ключа", StringComparison.OrdinalIgnoreCase)  => 5,
        SignatureTaskStatus.Skipped => 6,
        _ => 1
    };

    public string Message
    {
        get => _message;
        set
        {
            _message = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(GroupKey));
            OnPropertyChanged(nameof(GroupSortOrder));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
