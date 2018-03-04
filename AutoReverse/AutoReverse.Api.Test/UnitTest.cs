using System;
using System.Collections.Generic;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AutoReverse.Api.Test
{
    [TestClass]
    public class UnitTest
    {
        private static readonly byte[] BYTES = { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 };

        [TestMethod]
        public void Disassemble_x86_32()
        {
            var instructions = Disassembler.Disassemble_x86_32(BYTES);

            ShowInstructions(instructions);
        }

        [TestMethod]
        public void Disassemble_x86_64()
        {
            var instructions = Disassembler.Disassemble_x86_64(BYTES);

            ShowInstructions(instructions);
        }

        private static void ShowInstructions(IEnumerable<(ulong, byte[], ushort, string, string)> instructions)
        {
            foreach (var instr in instructions)
            {
                var bytesStr = string.Empty;
                for (var j = 0; j < instr.Item3; j++)
                {
                    if (j > 0)
                        bytesStr += " ";

                    bytesStr += $"{instr.Item2[j]:X2}";
                }

                Console.WriteLine($"{instr.Item1:X8}\t{bytesStr.PadRight(20)}\t{instr.Item4} {instr.Item5}");
            }
        }
    }
}
