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
        [TestMethod] public void Debug32_FILE_8bytes()
        {
            var expected = new CompareDebug
            {
                Id = 0x244,
                Address = 0x0,
                Bytes = new byte[] { 0x55 },
                Instruction = "push ebp",
                Registers = new[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }
            };

            using (var debugger = new Debugger(Deploy.FILE_8_BYTES))
                AssertDebugEquals(expected, debugger.Debug32());
        }
        [TestMethod] public void Debug32_FILE_Test_exe()
        {
            var expected = new CompareDebug
            {
                Id = 0x10a,
                Address = 0x1000,
                Bytes = new byte[] { 0xeb, 0x10 },
                Instruction = "jmp 0x12",
                Registers = new[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1012 }
            };

            using (var debugger = new Debugger(Deploy.FILE_TEST_EXE))
                AssertDebugEquals(expected, debugger.Debug32());
        }

        private static void WriteDebug(TextWriter writer, Debug32 debug32)
        {
            var strAddress = $"{debug32.Address:X8}";

            var strBytes = string.Empty;
            for (var j = 0; j < debug32.Bytes.Length; j++)
            {
                if (j > 0)
                    strBytes += " ";

                strBytes += $"{debug32.Bytes[j]:X2}";
            }
            
            writer.WriteLine($"{strAddress} {debug32.Instruction} ({strBytes})");
        }
        private static void AssertDebugEquals(IDebug expected, IDebug actual)
        {
            Assert.AreEqual(expected.Id, actual.Id);
            Assert.AreEqual(expected.Address, actual.Address);
            Assert.IsTrue(actual.Bytes.SequenceEqual(expected.Bytes));
            Assert.AreEqual(expected.Instruction, actual.Instruction);
            Assert.IsTrue(actual.Registers.SequenceEqual(expected.Registers));
        }

        private struct CompareDebug : IDebug
        {
            public int Id { get; set; }
            public int Address { get; set; }
            public byte[] Bytes { get; set; }
            public string Instruction { get; set; }
            public int[] Registers { get; set; }
        }
    }
}
