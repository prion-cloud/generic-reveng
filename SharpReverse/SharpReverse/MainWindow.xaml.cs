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

            TextBox.Text = string.Empty;

            _debugger = new Debugger(dialog.FileName);

            UpdateRegisterState();
        }

        private void Button_Step_Click(object sender, RoutedEventArgs e)
        {
            if (_debugger == null)
                return;

            var instruction = _debugger.Debug();

            var byteStr = string.Empty;
            foreach (var b in instruction.Bytes)
                byteStr += $"{b:x2} ";

            TextBox.Text += $"{instruction.Address:x8} {instruction.Instruction} ({byteStr.Substring(0, byteStr.Length - 1)})\r\n";

            UpdateRegisterState();
        }

        private void UpdateRegisterState()
        {
            var regState = _debugger.GetRegisterState();

            TbEax.Text = $"{regState.Registers[0]:x8}";
            TbEbx.Text = $"{regState.Registers[1]:x8}";
            TbEcx.Text = $"{regState.Registers[2]:x8}";
            TbEdx.Text = $"{regState.Registers[3]:x8}";
            TbEsp.Text = $"{regState.Registers[4]:x8}";
            TbEbp.Text = $"{regState.Registers[5]:x8}";
            TbEsi.Text = $"{regState.Registers[6]:x8}";
            TbEdi.Text = $"{regState.Registers[7]:x8}";
            TbEip.Text = $"{regState.Registers[8]:x8}";
        }
    }
}
