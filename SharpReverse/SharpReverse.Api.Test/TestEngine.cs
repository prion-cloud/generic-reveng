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
            var amd64 = @case.Amd64;

#if !WIN64
            if (amd64)
                Inconclusive("Expected platform configuration x64.");
#endif
            
            if (@case.Data is string path && !File.Exists(path))
                Inconclusive($"Apparent test file \"{path}\" not found.");

            using (var debugger = @case.DebuggerConstructor(@case.Data))
            {
                // ReSharper disable ConditionIsAlwaysTrueOrFalse

                AssertEqual(amd64, debugger.Amd64, $"{nameof(Debugger)}.{nameof(debugger.Amd64)}");

                foreach (var expected in @case.DebugResults)
                    AssertEqual(expected, (debugger.Debug(), debugger.InspectRegisters()), amd64);

                // ReSharper restore ConditionIsAlwaysTrueOrFalse
            }
        }
        
        private static void Inconclusive(string message)
        {
            throw new AssertInconclusiveException(message);
        }
        
        private static void AssertEqual((TestInstructionInfo, TestRegisterInfo) expected, (IInstructionInfo, IRegisterInfo) actual, bool amd64)
        {
            Console.WriteLine($"0x{actual.Item1.Address.ToString(amd64 ? "x16" : "x8")} | {actual.Item1.Instruction}");

            AssertEqual(expected.Item1.Id, actual.Item1.Id,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Id)}",
                i => $"0x{i:x}");

            AssertEqual(expected.Item1.Address, actual.Item1.Address,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Address)}",
                i => $"0x{i.ToString(amd64 ? "x16" : "x8")}");

            AssertEqual<byte>(expected.Item1.Bytes, actual.Item1.Bytes,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Bytes)}",
                i => $"0x{i:x2}");

            AssertEqual(expected.Item1.Instruction, actual.Item1.Instruction,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Instruction)}");

            AssertEqual(expected.Item2.Registers, actual.Item2.Registers.Select((a, i) =>
                {
                    if (expected.Item2.Masks.Select(m => m.Item1).Contains(i))
                        return a & expected.Item2.Masks.First(m => m.Item1 == i).Item2;
                    return a;
                }).ToArray(),
                $"{nameof(IRegisterInfo)}.{nameof(actual.Item2.Registers)}",
                i => $"0x{i.ToString(amd64 ? "x16" : "x8")}");
        }

        private static void AssertEqual<T>(T expected, T actual, string name)
        {
            AssertEqual(expected, actual, name, t => t.ToString());
        }
        private static void AssertEqual<T>(T expected, T actual, string name, Func<T, string> toString)
        {
            if (!Equals(expected, actual))
                throw new AssertFailedException($"{name}: '{toString(actual)}' / '{toString(expected)}'\n");
        }
        
        private static void AssertEqual<T>(T[] expected, T[] actual, string name, Func<T, string> toString)
        {
            AssertEqual(expected.Length, actual.Length, $"{name}.{nameof(actual.Length)}", i => i.ToString());

            for (var i = 0; i < expected.Length; i++)
                AssertEqual(expected[i], actual[i], $"{name}[{i}]", toString);
        }
    }
}
