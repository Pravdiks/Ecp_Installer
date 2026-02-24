using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace EcpInstaller.App.Helpers;

/// <summary>
/// Returns <c>true</c> for the "active tasks" group (items to install)
/// and <c>false</c> for "Пропущено …" groups so they start collapsed.
/// Used by the DataGrid GroupStyle to set <c>Expander.IsExpanded</c>.
/// </summary>
[ValueConversion(typeof(string), typeof(bool))]
public sealed class GroupExpandedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var name = value as string ?? string.Empty;
        // Skipped groups start collapsed; everything else expanded.
        return !name.StartsWith("Пропущено", StringComparison.OrdinalIgnoreCase);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => DependencyProperty.UnsetValue;
}
