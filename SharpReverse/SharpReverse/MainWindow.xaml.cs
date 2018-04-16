using System.ComponentModel;
using System.Windows;

using Microsoft.Win32;

using Superbr4in.SharpReverse.Api;
using Superbr4in.SharpReverse.Api.Factory;

namespace Superbr4in.SharpReverse
{
    public partial class MainWindow
    {
        private IDebugger _debugger;

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

            TextBoxIns.Text = string.Empty;

            _debugger = DebuggerFactory.CreateNew(dialog.FileName);

            UpdateRegisterState();
        }
        private void Button_Step_Click(object sender, RoutedEventArgs e)
        {
            if (_debugger == null)
                return;

            var ins = _debugger.Debug();
            
            TextBoxIns.Text += $"0x{ins.Address}  {ins.Instruction}" +
                               $"{(ins.Comment == string.Empty ? null : $" ({ins.Comment})")}\r\n";

            UpdateRegisterState();
        }
        private void Button_Memory_Click(object sender, RoutedEventArgs e)
        {
            if (_debugger == null)
                return;

            new MemoryWindow(_debugger.InspectMemory()).ShowDialog();
        }

        private void UpdateRegisterState()
        {
            TextBoxReg.Clear();

            foreach (var reg in _debugger.InspectRegisters())
                TextBoxReg.Text += $"{reg.Name.ToUpper()}: {reg.Value}\n";
        }
    }
}
