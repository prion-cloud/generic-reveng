using System;
using System.IO;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpReverse.Api.Test
{
    public static class TestEngine
    {
        public static void _Debugger_Debug<T>(DebuggerTestCase<T> @case)
        {
            var mode64 = @case.Mode64;

#if !WIN64
            if (mode64)
                Assert.Inconclusive("Expected x64 as target platform.");
#endif
            
            if (@case.Data is string path && !File.Exists(path))
                Assert.Inconclusive($"File \"{path}\" not found.");

            using (var debugger = @case.DebuggerConstructor(@case.Data))
            {
                Assert.AreEqual(mode64, debugger.Is64BitMode);

                foreach (var debug in @case.DebugInfos)
                {
                    Console.WriteLine($"0x{debug.Item1.Address.ToString(mode64 ? "x16" : "x8")} | {debug.Item1.Instruction}");
                    AssertEqual(debug, (debugger.Debug(), debugger.InspectRegisters()));
                }
            }
        }
        
        private static void AssertEqual((IInstructionInfo, IRegisterInfo) expected, (IInstructionInfo, IRegisterInfo) actual)
        {
            Assert.AreEqual(expected.Item1.Id, actual.Item1.Id, nameof(actual.Item1.Id));
            Assert.AreEqual(expected.Item1.Address, actual.Item1.Address, nameof(actual.Item1.Address));
            Assert.IsTrue(actual.Item1.Bytes.SequenceEqual(expected.Item1.Bytes), nameof(actual.Item1.Bytes));
            Assert.AreEqual(expected.Item1.Instruction, actual.Item1.Instruction, nameof(actual.Item1.Instruction));

            Assert.IsTrue(actual.Item2.Registers.SequenceEqual(expected.Item2.Registers), nameof(actual.Item2.Registers));
        }
    }
}
