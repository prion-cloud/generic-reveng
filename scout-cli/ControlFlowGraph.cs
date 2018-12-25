using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Cockpit;

using Unimage;

public partial class ControlFlowGraph : IDisposable
{
    private const char H  = '\u2500'; // │
    private const char V  = '\u2502'; // ─

    private const char UR = '\u2514'; // └
    private const char UL = '\u2518'; // ┘
    private const char DR = '\u250C'; // ┌
    private const char DL = '\u2510'; // ┐

    private const char UH = '\u2534'; // ┴
    private const char DH = '\u252C'; // ┬

    private readonly IntPtr _handle;

    private Block _root;

    public ControlFlowGraph(string executableFilePath)
    {
        _handle = CfgConstruct(executableFilePath);

        _root = new Block(CfgGetRoot(_handle));
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
        var instructionStrings =
            _root.Instructions
                .Select(ins => ins.ToString())
                .ToArray();

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
        CfgDestruct(_handle);
    }
}

public partial class Block
{
    private readonly IntPtr _handle;

    public Block(IntPtr handle)
    {
        _handle = handle;
    }

    public IEnumerable<Block> Successors
    {
        get
        {
            var nSuccessors = CfgBlockCountSuccessors(_handle);
            for (var successorIndex = 0; successorIndex < nSuccessors; successorIndex++)
                yield return new Block(CfgBlockGetSuccessor(_handle, successorIndex));
        }
    }

    public IEnumerable<Instruction> Instructions
    {
        get
        {
            var nInstructions = CfgBlockCountInstructions(_handle);
            for (var instructionIndex = 0; instructionIndex < nInstructions; instructionIndex++)
            {
                Instruction instruction;
                CfgBlockGetInstruction(_handle, instructionIndex, out instruction);

                yield return instruction;
            }
        }
    }
}

public partial struct Instruction
{
    public override string ToString()
    {
        return $"{_address:x} {_mnemonic} {Regex.Replace(_opStr, "0x([\\da-f]+)", "$1")}";
    }
}
