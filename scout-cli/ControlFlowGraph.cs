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
        var positionedBlocks = PositionBlocks(_root);

        var xSpaces = new int[positionedBlocks.Values.Max(v => v.X) + 1];
        var ySpaces = new int[positionedBlocks.Values.Max(v => v.Y) + 1];

        var visualizedBlocks =
            positionedBlocks
                .ToDictionary(
                    block => block.Value,
                    block =>
                        (TextShape)
                            new TextRectangle(
                                block.Value,
                                block.Key.Instructions
                                    .Select(instruction => instruction.ToString())
                                    .ToArray())
                                {
                                    TopLeft  = DR,
                                    TopRight = DL,

                                    BottomLeft  = UR,
                                    BottomRight = UL,

                                    HLine = H,
                                    VLine = V
                                });

        foreach (var block in visualizedBlocks.Values)
        {
            if (xSpaces[block.Position.X] < block.Size.X)
                xSpaces[block.Position.X] = block.Size.X;
            if (ySpaces[block.Position.Y] < block.Size.Y)
                ySpaces[block.Position.Y] = block.Size.Y;
        }

        var position = Vector.Zero;
        for (var y = 0; y < ySpaces.Length; y++)
        {
            var ySpace = ySpaces[y];

            for (var x = 0; x < xSpaces.Length; x++)
            {
                var xSpace = xSpaces[x];

                TextShape block;
                if (visualizedBlocks.TryGetValue(new Vector(x, y), out block))
                {
                    block.Position =
                        position +
                        new Vector(
                            xSpace / 2 - block.Size.X / 2,
                            ySpace / 2 - block.Size.Y / 2);
                }

                position.X += xSpace;
            }

            position.X = 0;
            position.Y += ySpace;
        }

        var canvas = new TextCanvas
        {
            { 0, visualizedBlocks.Values }
        };

        display.Content = canvas.Illustrate();

        /* TODO */

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

    private static Dictionary<Block, Vector> PositionBlocks(Block root)
    {
        var positionedBlocks = new Dictionary<Block, Vector>
        {
            { root, Vector.Zero }
        };
        var visited = new HashSet<Block>();

        PositionBlocks(root, ref positionedBlocks, ref visited);

        return positionedBlocks;
    }
    private static void PositionBlocks(
        Block parent,
        ref Dictionary<Block, Vector> positionedBlocks,
        ref HashSet<Block> visited)
    {
        visited.Add(parent);

        var parentPosition = positionedBlocks[parent];

        var uniqueChildIndex = 0;
        foreach (var child in parent.Children)
        {
            if (visited.Contains(child))
                continue;

            var newChildPosition =
                new Vector(
                    parentPosition.X + uniqueChildIndex,
                    parentPosition.Y + 1);

            Vector existingChildPosition;
            if (positionedBlocks.TryGetValue(child, out existingChildPosition))
            {
                if (existingChildPosition.Y > parentPosition.Y)
                    continue;

                positionedBlocks[child] =
                    new Vector(
                        existingChildPosition.X,
                        newChildPosition.Y);
            }
            else
            {
                positionedBlocks.Add(child, newChildPosition);

                uniqueChildIndex++;
            }

            PositionBlocks(child, ref positionedBlocks, ref visited);
        }

        visited.Remove(parent);
    }
}

public partial class Block
{
    private readonly IntPtr _handle;

    public Block(IntPtr handle)
    {
        _handle = handle;
    }

    public IEnumerable<Block> Children
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

    public override bool Equals(object obj)
    {
        var other = obj as Block;
        if (other == null)
            return false;

        return other._handle == _handle;
    }

    public override int GetHashCode()
    {
        return _handle.GetHashCode();
    }
}

public partial struct Instruction
{
    public override string ToString()
    {
        return $"{_address:x} {_mnemonic} {Regex.Replace(_opStr, "0x([\\da-f]+)", "$1")}";
    }
}
