using System;
using System.Collections.Generic;
using System.IO;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AutoReverse.Api.Test
{
    [TestClass]
    [DeploymentItem(PInvoke.DLL_NAME)]
    [DeploymentItem(Deploy.FOLDER, Deploy.FOLDER)]
    public class UnitTest
    {
        [TestMethod]
        public void Disassemble_x86_32_File_8bytes()
        {
            var instructions = Disassembler.Disassemble_x86_32(new FileInfo(Deploy.FILE_8_BYTES).FullName);

            WriteInstructions(Console.Out, instructions);
        }

        [TestMethod]
        public void Disassemble_x86_32_File_stack1()
        {
            var instructions = Disassembler.Disassemble_x86_32(new FileInfo(Deploy.FILE_STACK_1).FullName);

            using (var file = File.Create(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\output.txt"))
            using (var writer = new StreamWriter(file))
                WriteInstructions(writer, instructions);
        }

        private static void WriteInstructions(TextWriter writer, IEnumerable<(ulong, byte[], ushort, string, string)> instructions)
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

                writer.WriteLine($"{instr.Item1:X8}\t{bytesStr.PadRight(20)}\t{instr.Item4} {instr.Item5}");
            }
        }
    }
}
