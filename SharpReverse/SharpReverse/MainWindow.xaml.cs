using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using Microsoft.Win32;

using Superbr4in.SharpReverse.Api;

namespace Superbr4in.SharpReverse
{
    public partial class MainWindow
    {
        private Debugger _debugger;

        private string Format => _debugger.Amd64 ? "x16" : "x8";

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
            for (var i = 0; i < instruction.Bytes.Length; i++)
            {
                if (i > 0)
                    byteStr += " ";

                byteStr += $"{instruction.Bytes[i]:x2}";
            }

            TextBox.Text += $"{instruction.Address.ToString(Format)} {instruction.Instruction} ({byteStr})\r\n";

            UpdateRegisterState();
        }

        private void UpdateRegisterState()
        {
            var regState = _debugger.InspectRegisters();
            
            var tbs = TbGrid.Children.OfType<TextBox>().ToArray();

            for (var i = 0; i < tbs.Length; i++)
            {
                var prev = tbs[i].Text;
                var cur = regState.Registers[i].ToString(Format);

                if (prev != string.Empty && cur != prev)
                    tbs[i].Foreground = new SolidColorBrush(Colors.Red);
                else tbs[i].Foreground = new SolidColorBrush(Colors.Black);

                tbs[i].Text = cur;
            }
        }
    }
}
