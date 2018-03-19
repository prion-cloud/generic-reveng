using System.ComponentModel;
using System.Windows;

using Microsoft.Win32;

using SharpReverse.Api;

namespace SharpReverse
{
    public partial class MainWindow
    {
        private Debugger _debugger;

        public MainWindow()
        {
            InitializeComponent();

            _debugger = null;
        }

        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            _debugger?.Dispose();
        }

        private void Button_Load_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "All files|*.*"
            };

            if (!dialog.ShowDialog(this).Value)
                return;

            TextBlock.Text = string.Empty;

            _debugger = new Debugger(dialog.FileName);
        }

        private void Button_Step_Click(object sender, RoutedEventArgs e)
        {
            if (_debugger == null)
                return;

            var debug = _debugger.Debug32();

            TextBlock.Text += $"0x{debug.Address:x8} {debug.Instruction}\n";
        }
    }
}
