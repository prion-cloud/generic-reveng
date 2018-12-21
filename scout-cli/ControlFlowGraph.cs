using System;
using System.Text.RegularExpressions;

using Cockpit;

using Unimage;

public class ControlFlowGraph : IDisposable
{
    private const char H  = '\u2500'; // │
    private const char V  = '\u2502'; // ─

    private const char UR = '\u2514'; // └
    private const char UL = '\u2518'; // ┘
    private const char DR = '\u250C'; // ┌
    private const char DL = '\u2510'; // ┐

    private const char UH = '\u2534'; // ┴
    private const char DH = '\u252C'; // ┬

    private readonly IntPtr _controlFlowHandle;

    public ControlFlowGraph(string executableFilePath)
    {
        _controlFlowHandle = Scout.CreateControlFlow(executableFilePath);
    }
    ~ControlFlowGraph()
    {
        ReleaseHandle();
    }

    public void Dispose()
    {
        ReleaseHandle();
        GC.SuppressFinalize(this);
    }

    public void Show(ITextDisplay display)
    {
        var rootBlockHandle = Scout.GetRootBlock(_controlFlowHandle);

        var instructionCount = Scout.CountBlockInstructions(rootBlockHandle);
        var instructionStrings = new string[instructionCount];
        for (var i = 0; i < instructionCount; i++)
        {
            Scout.Instruction instruction;
            Scout.DisassembleBlockInstruction(rootBlockHandle, i, out instruction);

            instructionStrings[i] = GetInstructionString(instruction);
        }

        var canvas = new TextCanvas();
        canvas[0].Add(
            new TextRectangle(0, 0, instructionStrings)
            {
                TopLeft  = DR,
                TopRight = DL,

                BottomLeft  = UR,
                BottomRight = UL,

                HLine = H,
                VLine = V
            });

        /* TODO */

        display.Content = canvas.Illustrate();

        var loop = true;
        do
        {
            display.Status = $"({display.Line}, {display.Column})";

            switch (Console.ReadKey(true).Key)
            {
            case ConsoleKey.UpArrow:
                display.Line--;
                break;
            case ConsoleKey.LeftArrow:
                display.Column--;
                break;
            case ConsoleKey.DownArrow:
                display.Line++;
                break;
            case ConsoleKey.RightArrow:
                display.Column++;
                break;
            case ConsoleKey.X:
                loop = false;
                break;
            }
        }
        while (loop);
    }

    private void ReleaseHandle()
    {
        Scout.ReleaseControlFlowHandle(_controlFlowHandle);
    }

    private static string GetInstructionString(Scout.Instruction instruction)
    {
        return
            $"{instruction.Address:x} {instruction.Mnemonic} " +
            $"{Regex.Replace(instruction.OpStr, "0x([\\da-f]+)", "$1")}";
    }
}
