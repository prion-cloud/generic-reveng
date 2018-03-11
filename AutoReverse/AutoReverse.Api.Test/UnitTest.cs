using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AutoReverse.Api.Test
{
    [TestClass]
    [DeploymentItem(PInvoke.DLL_NAME)]
    [DeploymentItem(Deploy.FOLDER, Deploy.FOLDER)]
    public class UnitTest
    {
        [TestMethod] public void Disassemble_x86_32_File_8bytes()
        {
            var actual = Disassembler.Disassemble_x86_32(Deploy.FILE_8_BYTES).ToArray();

            WriteInstructions(Console.Out, actual);

            var expected = new[]
            {
                new AsmInstruction(0x0, new byte[] { 0x55 }, "push", "ebp"),
                new AsmInstruction(0x1, new byte[] { 0x48 }, "dec", "eax"),
                new AsmInstruction(0x2, new byte[] { 0x8B, 0x05, 0xB8, 0x13, 0x00, 0x00 }, "mov", "eax, dword ptr [0x13b8]")
            };

            AssertInstructionArrayEquals(expected, actual);
        }
        [TestMethod] public void Disassemble_x86_32_File_lea()
        {
            var actual = Disassembler.Disassemble_x86_32(Deploy.FILE_LEA).ToArray();

            WriteInstructions(Console.Out, actual);

            var expected = new[]
            {
                new AsmInstruction(0x0, new byte[] { 0x8D, 0x95, 0xD4, 0xFE, 0xFF, 0xFF }, "lea", "edx, dword ptr [ebp - 0x12c]")
            };

            AssertInstructionArrayEquals(expected, actual);
        }

        [TestMethod] public void Disassemble_x86_32_File_Test_exe()
        {
            var instructions = Disassembler.Disassemble_x86_32(Deploy.FILE_TEST_EXE).ToArray();

            using (var file = File.Create(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\output_test_exe.txt"))
            using (var writer = new StreamWriter(file))
                WriteInstructions(writer, instructions);
        }

        private static void WriteInstructions(TextWriter writer, IEnumerable<AsmInstruction> instructions)
        {
            foreach (var ins in instructions)
            {
                var strAddress = $"{ins.Address:X8}";

                var strBytes = string.Empty;
                for (var j = 0; j < ins.Bytes.Length; j++)
                {
                    if (j > 0)
                        strBytes += " ";

                    strBytes += $"{ins.Bytes[j]:X2}";
                }
                
                var res = $"{strAddress}: ";

                if (ins.Mnemonic == null)
                    res += $"; {strBytes}";
                else
                    res += $"  {ins.Mnemonic} {ins.Operands} ({strBytes})";

                writer.WriteLine(res);
            }
        }
        private static void AssertInstructionArrayEquals(AsmInstruction[] expected, AsmInstruction[] actual)
        {
            Assert.AreEqual(expected.Length, actual.Length);

            for (var i = 0; i < expected.Length; i++)
            {
                var exp = expected[i];
                var act = actual[i];

                Assert.AreEqual(exp.Address, act.Address);

                Assert.IsTrue(act.Bytes.SequenceEqual(exp.Bytes));

                Assert.AreEqual(exp.Mnemonic, act.Mnemonic);
                Assert.AreEqual(exp.Operands, act.Operands);
            }
        }
    }
}
