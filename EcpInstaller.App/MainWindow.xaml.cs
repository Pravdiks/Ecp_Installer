using EcpInstaller.App.Models;
using EcpInstaller.App.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace EcpInstaller.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly ScanService _scanService;
    private readonly InstallService _installService;
    private readonly AppLogger _logger;
    private readonly SettingsService _settingsService;
    private readonly HashSet<string> _inputPaths = new(StringComparer.OrdinalIgnoreCase);
    private string? _settingsPath;

    public MainWindow()
    {
        InitializeComponent();

        var appDirectory = AppContext.BaseDirectory;
        _logger = new AppLogger(appDirectory);
        _scanService = new ScanService();
        var cryptoCli = new CryptoProCliService(_logger);
        _installService = new InstallService(_logger, new InstallerService(_logger, cryptoCli));
        _settingsService = new SettingsService();

        Tasks = [];
        Logs = _logger.UiLogs;
        DataContext = this;

        LoadSettings();
        _logger.Info("Приложение запущено.");
    }

    public ObservableCollection<SignatureTask> Tasks { get; }

    public ObservableCollection<string> Logs { get; }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        ContainerOption_Changed(sender, e);
        FocusPasteSurface();
    }

    private void PickInput_Click(object sender, RoutedEventArgs e)
    {
        var ofd = new Microsoft.Win32.OpenFileDialog
        {
            Multiselect = true,
            Filter = "Все файлы|*.*"
        };

        if (ofd.ShowDialog() == true)
        {
            var added = AddInputPaths(ofd.FileNames);
            _logger.Info($"Добавлено файлов: {added}");
        }

        using var folderDialog = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Дополнительно можно выбрать папку для сканирования"
        };

        if (folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            AddInputPaths([folderDialog.SelectedPath]);
            _logger.Info($"Добавлена папка: {folderDialog.SelectedPath}");
        }

        RunScan();
    }

    private void Scan_Click(object sender, RoutedEventArgs e) => RunScan();

    private void RunScan()
    {
        Tasks.Clear();
        foreach (var task in _scanService.Scan(_inputPaths, _logger, MostActualCheck.IsChecked == true, PasswordBox.Text))
        {
            Tasks.Add(task);
        }

        // Apply grouping and ordering: install tasks first, errors second, skipped last.
        var view = CollectionViewSource.GetDefaultView(Tasks);
        view.GroupDescriptions.Clear();
        view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(SignatureTask.GroupKey)));
        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new SortDescription(nameof(SignatureTask.GroupSortOrder), ListSortDirection.Ascending));

        if (Tasks.Count == 0)
        {
            _logger.Warn("Поддерживаемые ЭЦП не найдены. Мусорные файлы (PDF/DOCX/JPG/PNG/MP4 и т.д.) проигнорированы.");
        }
    }

    private async void InstallAll_Click(object sender, RoutedEventArgs e)
    {
        if (Tasks.Count == 0)
        {
            _logger.Warn("Список задач пуст. Сначала выполните сканирование.");
            return;
        }

        var storeLocation = GetStoreLocation();
        if (storeLocation == StoreLocation.LocalMachine && !Helpers.WindowsPrincipalHelper.IsAdministrator())
        {
            var result = System.Windows.MessageBox.Show(
                "Для установки в LocalMachine требуются права администратора. Установить в CurrentUser без админа?",
                "Недостаточно прав",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                StoreCombo.SelectedIndex = 0;
                storeLocation = StoreLocation.CurrentUser;
                _logger.Warn("Пользователь переключился на CurrentUser из-за отсутствия админ-прав.");
            }
            else
            {
                _logger.Warn("Установка прервана пользователем: LocalMachine без админ-прав.");
                return;
            }
        }

        var containerLocation = RegistryOption.IsChecked == true ? ContainerLocation.Registry : ContainerLocation.Disk;

        var password = PasswordBox.Text;
        var containerFolder = ContainerFolderBox.Text;

        Progress.Value = 0;
        var installable = Tasks.Where(t => t.Status != SignatureTaskStatus.Skipped).ToList();
        if (installable.Count == 0)
        {
            _logger.Warn("Нет задач для установки: все элементы пропущены правилами отбора.");
            return;
        }

        var done = 0;
        foreach (var task in installable)
        {
            await _installService.InstallAsync(task, password, storeLocation, containerLocation, containerFolder);
            done++;
            Progress.Value = (double)done / installable.Count * 100;
        }

        _logger.Info("Установка всех задач завершена.");
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        Tasks.Clear();
        _inputPaths.Clear();
        Progress.Value = 0;
        _logger.Info("Список очищен.");
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(_logger.LogPath))
        {
            _logger.Warn("Лог-файл еще не создан.");
            return;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = _logger.LogPath,
            UseShellExecute = true
        });
    }

    private void OpenCertificates_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "certmgr.msc",
                UseShellExecute = true
            });
            _logger.Info("Открыта оснастка 'Сертификаты (текущий пользователь)'.");
        }
        catch (Exception ex)
        {
            _logger.Error($"Не удалось открыть certmgr.msc: {ex.Message}");
            System.Windows.MessageBox.Show(
                "Не удалось открыть список личных сертификатов. Откройте вручную certmgr.msc.",
                "Ошибка",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ViewInstalled_Click(object sender, RoutedEventArgs e)
    {
        if (RegistryOption.IsChecked == true)
        {
            ShowCurrentUserCertificates();
            return;
        }

        try
        {
            var path = string.IsNullOrWhiteSpace(ContainerFolderBox.Text) ? ResolveDefaultContainerFolder() : ContainerFolderBox.Text;
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
            _logger.Info($"Открыта папка контейнеров: {path}");
        }
        catch (Exception ex)
        {
            _logger.Error($"Не удалось открыть папку контейнеров: {ex.Message}");
            System.Windows.MessageBox.Show($"Не удалось открыть папку контейнеров: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ShowCurrentUserCertificates()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var items = store.Certificates.Cast<X509Certificate2>()
            .OrderByDescending(c => c.NotAfter)
            .Select(c => new
            {
                c.Subject,
                c.Issuer,
                c.SerialNumber,
                c.Thumbprint,
                NotAfter = c.NotAfter.ToString("yyyy-MM-dd"),
                HasPrivateKey = c.HasPrivateKey ? "Да" : "Нет"
            })
            .ToList();

        var grid = new DataGrid
        {
            ItemsSource = items,
            IsReadOnly = true,
            AutoGenerateColumns = true
        };

        var viewer = new Window
        {
            Title = "Установленные сертификаты CurrentUser\\My",
            Owner = this,
            Width = 980,
            Height = 460,
            Content = grid
        };
        viewer.ShowDialog();
    }

    private void PickContainerFolder_Click(object sender, RoutedEventArgs e)
    {
        using var folderDialog = new System.Windows.Forms.FolderBrowserDialog
        {
            SelectedPath = ContainerFolderBox.Text
        };

        if (folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            ContainerFolderBox.Text = folderDialog.SelectedPath;
            _logger.Info($"Выбрана папка контейнеров: {folderDialog.SelectedPath}");
            SaveSettings();
        }
    }

    private void ContainerOption_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (ContainerFolderBox == null || WarningText == null) return;

        var isDisk = DiskOption.IsChecked == true;
        ContainerFolderBox.IsEnabled = isDisk;
        WarningText.Text = isDisk ? string.Empty : "Режим реестра использует CurrentUser и не требует админ-прав.";
        SaveSettings();
    }

    private void TopMostCheck_Changed(object sender, RoutedEventArgs e)
    {
        Topmost = TopMostCheck.IsChecked == true;
        SaveSettings();
    }

    private void Window_DragEnter(object sender, System.Windows.DragEventArgs e) => ShowDropOverlay();

    private void Window_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        var hasDrop = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop);
        e.Effects = hasDrop ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
        e.Handled = true;

        if (hasDrop)
        {
            ShowDropOverlay();
        }
        else
        {
            HideDropOverlay();
        }
    }

    private void Window_DragLeave(object sender, System.Windows.DragEventArgs e) => HideDropOverlay();

    private void Window_Drop(object sender, System.Windows.DragEventArgs e)
    {
        HideDropOverlay();

        if (!e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
        {
            return;
        }

        var dropped = (string[])e.Data.GetData(System.Windows.DataFormats.FileDrop);
        var added = AddInputPaths(dropped);
        _logger.Info($"Добавлено drag&drop элементов: {added} из {dropped.Length}");
        RunScan();
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != Key.V || Keyboard.Modifiers != ModifierKeys.Control)
        {
            return;
        }

        if (TryPastePathsFromClipboard("Ctrl+V"))
        {
            e.Handled = true;
        }
    }

    private void PasteCommand_CanExecute(object sender, CanExecuteRoutedEventArgs e)
    {
        e.CanExecute = true;
        e.Handled = true;
    }

    private void PasteCommand_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (TryPastePathsFromClipboard("Команда вставки"))
        {
            e.Handled = true;
        }
    }

    private bool TryPastePathsFromClipboard(string source)
    {
        var validPaths = ReadPathsFromClipboard();
        if (validPaths.Count == 0)
        {
            _logger.Info($"{source}: вставка из буфера проигнорирована (не найдено валидных путей).");
            return false;
        }

        var added = AddInputPaths(validPaths);
        _logger.Info($"Вставлено из буфера: {added} путей");
        foreach (var path in validPaths)
        {
            _logger.Info($"Буфер: {path}");
        }

        if (added > 0)
        {
            RunScan();
            return true;
        }

        _logger.Info($"{source}: все пути из буфера уже были добавлены ранее.");
        return false;
    }

    private List<string> ReadPathsFromClipboard()
    {
        var result = new List<string>();

        if (System.Windows.Clipboard.ContainsFileDropList())
        {
            var dropped = System.Windows.Clipboard.GetFileDropList();
            foreach (var item in dropped.Cast<string>())
            {
                if (File.Exists(item) || Directory.Exists(item))
                {
                    result.Add(item);
                }
            }
        }

        if (result.Count > 0)
        {
            return result;
        }

        if (!System.Windows.Clipboard.ContainsText())
        {
            return result;
        }

        var text = System.Windows.Clipboard.GetText();
        var candidates = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate) || Directory.Exists(candidate))
            {
                result.Add(candidate);
            }
        }

        return result;
    }

    private void PasteZone_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        FocusPasteSurface();
        e.Handled = true;
    }

    private void WindowSurface_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source && IsInteractiveControl(source))
        {
            return;
        }

        FocusPasteSurface();
    }

    private void LogsListBox_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e) => FocusPasteSurface();

    private void FocusPasteSurface()
    {
        Activate();
        Focus();
        Keyboard.Focus(PasteZone);
    }

    private static bool IsInteractiveControl(DependencyObject source)
    {
        DependencyObject? current = source;
        while (current != null)
        {
            if (current is System.Windows.Controls.TextBox
                or System.Windows.Controls.ComboBox
                or System.Windows.Controls.Button
                or System.Windows.Controls.CheckBox
                or System.Windows.Controls.RadioButton
                or System.Windows.Documents.Hyperlink)
            {
                return true;
            }

            current = current switch
            {
                Visual visual => VisualTreeHelper.GetParent(visual),
                System.Windows.Media.Media3D.Visual3D visual3D => VisualTreeHelper.GetParent(visual3D),
                System.Windows.FrameworkContentElement contentElement => contentElement.Parent,
                _ => LogicalTreeHelper.GetParent(current)
            };
        }

        return false;
    }

    private int AddInputPaths(IEnumerable<string> paths)
    {
        var added = 0;
        foreach (var path in paths)
        {
            if (!(File.Exists(path) || Directory.Exists(path)))
            {
                continue;
            }

            var full = Path.GetFullPath(path);
            if (_inputPaths.Add(full))
            {
                added++;
                continue;
            }

            _logger.Info($"Пропущено: уже добавлено '{full}'");
        }

        return added;
    }

    private StoreLocation GetStoreLocation()
    {
        var selected = StoreCombo.SelectedItem as ComboBoxItem;
        return string.Equals(selected?.Tag?.ToString(), "LocalMachine", StringComparison.OrdinalIgnoreCase)
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;
    }

    private string ResolveDefaultContainerFolder()
    {
        const string defaultFolderName = "EcpInstallerContainers";
        const string preferredRoot = @"D:\";
        if (Directory.Exists(preferredRoot))
        {
            return Path.Combine(preferredRoot, defaultFolderName);
        }

        const string fallbackRoot = @"C:\";
        WarningText.Text = "Диск D: не найден, используется C:.";
        _logger.Warn("Диск D: не найден. Автовыбор пути контейнеров: C:\\EcpInstallerContainers");
        return Path.Combine(fallbackRoot, defaultFolderName);
    }

    private void ShowDropOverlay() => DropOverlay.Visibility = Visibility.Visible;

    private void HideDropOverlay() => DropOverlay.Visibility = Visibility.Collapsed;

    private void LoadSettings()
    {
        var loaded = _settingsService.Load(_logger);
        _settingsPath = loaded.Path;
        var settings = loaded.Settings;

        PasswordBox.Text = settings.Password;
        TopMostCheck.IsChecked = settings.TopMost;
        Topmost = settings.TopMost;
        MostActualCheck.IsChecked = settings.OnlyMostActualCertificate;

        var isRegistry = settings.ContainerLocation == ContainerLocation.Registry;
        RegistryOption.IsChecked = isRegistry;
        DiskOption.IsChecked = !isRegistry;

        ContainerFolderBox.Text = string.IsNullOrWhiteSpace(settings.ContainerFolder) ? ResolveDefaultContainerFolder() : settings.ContainerFolder;

        foreach (var item in StoreCombo.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), settings.StoreLocationTag, StringComparison.OrdinalIgnoreCase))
            {
                StoreCombo.SelectedItem = item;
                break;
            }
        }

        ContainerOption_Changed(this, new RoutedEventArgs());
    }

    private void SaveSettings()
    {
        if (!IsLoaded)
        {
            return;
        }

        var settings = new AppSettings
        {
            Password = PasswordBox.Text,
            ContainerLocation = RegistryOption.IsChecked == true ? ContainerLocation.Registry : ContainerLocation.Disk,
            ContainerFolder = string.IsNullOrWhiteSpace(ContainerFolderBox.Text) ? ResolveDefaultContainerFolder() : ContainerFolderBox.Text,
            TopMost = TopMostCheck.IsChecked == true,
            StoreLocationTag = (StoreCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "CurrentUser",
            OnlyMostActualCertificate = MostActualCheck.IsChecked == true
        };

        _settingsService.Save(settings, _settingsPath, _logger);
    }


    private void SettingsControl_Changed(object sender, RoutedEventArgs e) => SaveSettings();

    private void SettingsControl_Changed(object sender, TextChangedEventArgs e) => SaveSettings();

    private void SettingsControl_Changed(object sender, SelectionChangedEventArgs e) => SaveSettings();

    private void TelegramLink_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://t.me/Pravdiks",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.Error($"Не удалось открыть Telegram-ссылку: {ex.Message}");
            System.Windows.MessageBox.Show(
                "Не удалось открыть ссылку Telegram. Проверьте настройки браузера по умолчанию.",
                "Ошибка открытия ссылки",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }

    }

    protected override void OnClosing(CancelEventArgs e)
    {
        SaveSettings();
        base.OnClosing(e);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
