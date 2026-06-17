using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using HookMonitor.Models;

namespace HookMonitor.GUI.Converters;

/// <summary>
/// 威胁等级到颜色转换器
/// </summary>
public class ThreatLevelToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)), // 红色
                ThreatLevel.High => new SolidColorBrush(Color.FromRgb(0xEA, 0x58, 0x0C)),     // 橙色
                ThreatLevel.Medium => new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06)),   // 黄色
                ThreatLevel.Low => new SolidColorBrush(Color.FromRgb(0x25, 0x5E, 0xC4)),      // 蓝色
                _ => new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80))                     // 灰色
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// 威胁等级到文字转换器
/// </summary>
public class ThreatLevelToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => "严重",
                ThreatLevel.High => "高危",
                ThreatLevel.Medium => "中等",
                ThreatLevel.Low => "低危",
                _ => "无"
            };
        }
        return "未知";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// 文件大小格式化转换器
/// </summary>
public class FileSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is long size)
        {
            string[] units = ["B", "KB", "MB", "GB"];
            var unitIndex = 0;
            var displaySize = (double)size;
            while (displaySize >= 1024 && unitIndex < units.Length - 1)
            {
                displaySize /= 1024;
                unitIndex++;
            }
            return $"{displaySize:F1} {units[unitIndex]}";
        }
        return value?.ToString() ?? string.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Null到Visibility转换器
/// </summary>
public class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value == null ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// 非Null到Visibility转换器
/// </summary>
public class NotNullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value != null ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
