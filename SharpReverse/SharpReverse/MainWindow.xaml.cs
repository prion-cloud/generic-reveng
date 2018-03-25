using System;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

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

            var addrStr = string.Empty;

            switch (_debugger.TargetMachine)
            {
                case TargetMachine.x86_32:
                    addrStr = instruction.Address.ToString("x8");
                    break;
                case TargetMachine.x86_64:
                    addrStr = instruction.Address.ToString("x16");
                    break;
            }

            var byteStr = string.Empty;
            for (var i = 0; i < instruction.Bytes.Length; i++)
            {
                if (i > 0)
                    byteStr += " ";

                byteStr += $"{instruction.Bytes[i]:x2}";
            }

            TextBox.Text += $"{addrStr} {instruction.Instruction} ({byteStr})\r\n";

            UpdateRegisterState();
        }

        private void UpdateRegisterState()
        {
            var regState = _debugger.InspectRegisters();

            string format;
            switch (_debugger.TargetMachine)
            {
                case TargetMachine.x86_32:
                    format = "x8";
                    break;
                case TargetMachine.x86_64:
                    format = "x16";
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            var tbs = TbGrid.Children.OfType<TextBox>().ToArray();

            for (var i = 0; i < tbs.Length; i++)
            {
                var prev = tbs[i].Text;
                var cur = regState.Registers[i].ToString(format);

                if (prev != string.Empty && cur != prev)
                    tbs[i].Foreground = new SolidColorBrush(Colors.Red);
                else tbs[i].Foreground = new SolidColorBrush(Colors.Black);

                tbs[i].Text = cur;
            }
        }
    }
}
