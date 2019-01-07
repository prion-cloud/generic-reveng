using System;
using System.IO;

using Cockpit;

public static class Scout
{
    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Invalid argument(s)");
            return 1;
        }

        var filePath = args[0];

        if (!File.Exists(filePath))
        {
            Console.Error.WriteLine("Invalid file");
            return 1;
        }

        using (var cfg = new ControlFlowGraph(filePath))
        {
            var display = ConsoleDisplay.Instance;
            display.Show();

            cfg.Show(ConsoleDisplay.Instance);

            display.Hide();
        }

        return 0;
    }
}
