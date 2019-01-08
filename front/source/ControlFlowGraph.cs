using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Cockpit;

using Unimage;

public partial class ControlFlowGraph : IDisposable
{
    private const char CH_H  = '\u2500'; // │
    private const char CH_V  = '\u2502'; // ─

    private const char CH_UR = '\u2514'; // └
    private const char CH_UL = '\u2518'; // ┘
    private const char CH_DR = '\u250C'; // ┌
    private const char CH_DL = '\u2510'; // ┐

    private const char CH_UH = '\u2534'; // ┴
    private const char CH_DH = '\u252C'; // ┬

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
        var canvas = new TextCanvas();
        Paint(canvas);

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

    private void Paint(TextCanvas canvas)
    {
        // Block -> Vector
        var positionedBlocks = PositionBlocks(_root);

        /*

        +---+---+---+---+
        | A |   |   |   |
        +---+---+---+---+
        |   | D |   |   |
        +---+---+---+---+
        | B | E |   |   |
        +---+---+---+---+
        |   | F | H |   |
        +---+---+---+---+
        | C | G | I | J |
        +---+---+---+---+

        */

        // Vector -> TextRectangle
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
                                    ChTopLft = CH_DR,
                                    ChTopRgt = CH_DL,

                                    ChBotLft = CH_UR,
                                    ChBotRgt = CH_UL,

                                    ChHrz = CH_H,
                                    ChVrt = CH_V
                                });

        canvas.Add(0, visualizedBlocks.Values);

        var xSpaces = new int[visualizedBlocks.Keys.Max(v => v.X) + 1];
        var ySpaces = new int[visualizedBlocks.Keys.Max(v => v.Y) + 1];
        foreach (var block in visualizedBlocks.Values)
        {
            xSpaces[block.Position.X] = Math.Max(xSpaces[block.Position.X], block.Size.X);
            ySpaces[block.Position.Y] = Math.Max(ySpaces[block.Position.Y], block.Size.Y);
        }

        /*

        +----+---+------+-----+
        |    |   |      |     |
        |    |   |      |     |
        +----+---+------+-----+
        |    |   |      |     |
        |    |   |      |     |
        |    |   |      |     |
        +----+---+------+-----+
        |    |   |      |     |
        +----+---+------+-----+
        |    |   |      |     |
        |    |   |      |     |
        |    |   |      |     |
        |    |   |      |     |
        +----+---+------+-----+
        |    |   |      |     |
        |    |   |      |     |
        |    |   |      |     |
        +----+---+------+-----+

        */

        const int BLOCK_GAP = 1;

        var position = Vector.Zero;
        for (var y = 0; y < ySpaces.Length; y++)
        {
            var ySpace = ySpaces[y];

            for (var x = 0; x < xSpaces.Length; x++)
            {
                var xSpace = xSpaces[x];

                TextShape block;
                if (visualizedBlocks.TryGetValue(new Vector(x, y), out block))
                    block.Position = position + new Vector(xSpace / 2 - block.Size.X / 2, 0);

                position.X += xSpace + BLOCK_GAP;
            }

            position.X = 0;
            position.Y += ySpace + BLOCK_GAP;
        }

        /*

        +----+---+------+-----+
        | xx |   |      |     |
        | xx |   |      |     |
        +----+---+------+-----+
        |    | x |      |     |
        |    | x |      |     |
        |    | x |      |     |
        +----+---+------+-----+
        |  x | x |      |     |
        +----+---+------+-----+
        |    | x | xxxx |     |
        |    | x | xxxx |     |
        |    |   | xxxx |     |
        |    |   | xxxx |     |
        +----+---+------+-----+
        | xx | x |  xx  | xxx |
        | xx |   |  xx  |     |
        |    |   |  xx  |     |
        +----+---+------+-----+

        */

        foreach (var parent in positionedBlocks)
        {
            var parentView = visualizedBlocks[parent.Value];

            foreach (var child in parent.Key.Children)
            {
                var childView = visualizedBlocks[positionedBlocks[child]];

                var start = parentView.Position +
                    new Vector(parentView.Size.X / 2, parentView.Size.Y - 1);
                var end = childView.Position +
                    new Vector(childView.Size.X / 2, 0);

                var diff = end - start;

                if (diff.Y < 0)
                {
                    /* TODO */
                    continue;
                }

                canvas[1].Add(
                    new TextLineV(start, diff.Y)
                    {
                        ChTop = CH_DH,
                        ChBot = CH_V,

                        ChVrt = CH_V
                    });
                canvas[1].Add(
                    new TextDot(end)
                    {
                        ChBdy = CH_UH
                    });

                if (diff.X == 0)
                    continue;

                canvas[2].Add(
                    new TextLineH(new Vector(start.X, end.Y - 1), diff.X + Math.Sign(diff.X))
                    {
                        ChLft = diff.X > 0 ? CH_UR : CH_DR,
                        ChRgt = diff.X > 0 ? CH_DL : CH_UL,

                        ChHrz = CH_H
                    });
            }
        }

        /*

        +----+---+------+-----+
        | xx                  |
        | xx                  |
        +  . . .              +
        |  .   x              |
        |  .   x              |
        |  .   x              |
        +  . . .              +
        |  x   x              |
        +  .   . . . .        +
        |  .   x   xxxx       |
        |  .   x   xxxx       |
        |  .   .   xxxx       |
        |  .   .   xxxx       |
        +  . . .     . . . .  +
        | xx   x    xx    xxx |
        | xx        xx        |
        |           xx        |
        +----+---+------+-----+

        */
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
