using System;
using System.IO;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Superbr4in.SharpReverse.Api.Test
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
            var format = amd64 ? "x16" : "x8";

            Console.WriteLine($"0x{actual.Item1.Address.ToString(format)} | {actual.Item1.Instruction}");

            AssertEqual(expected.Item1.Id, actual.Item1.Id,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Id)}", i => $"0x{i:x}");

            AssertEqual(expected.Item1.Address, actual.Item1.Address,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Address)}", format);

            AssertArrayEqual<byte>(expected.Item1.Bytes, actual.Item1.Bytes,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Bytes)}", i => $"0x{i:x2}");

            AssertEqual(expected.Item1.Instruction, actual.Item1.Instruction,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Instruction)}");

            AssertArrayEqual(expected.Item2.Registers, actual.Item2.Registers,
                $"{nameof(IRegisterInfo)}.{nameof(actual.Item2.Registers)}", format);
        }

        private static void AssertEqual<T>(T expected, T actual, string description)
        {
            AssertEqual(expected, actual, description, t => t.ToString());
        }
        private static void AssertEqual<T>(T expected, T actual, string description, Func<T, string> toString)
        {
            if (!Equals(expected, actual))
                throw new AssertFailedException($"{description}: '{toString(actual)}' / '{toString(expected)}'\n");
        }
        private static void AssertEqual((ulong, ulong?) expected, ulong actual, string description, string format)
        {
            AssertEqual(
                expected.Item1,
                actual & (expected.Item2 ?? actual),
                description,
                ul => ul.ToString(format));
        }
        
        private static void AssertArrayEqual<T>(T[] expected, T[] actual, string name, Func<T, string> toString)
        {
            AssertEqual(expected.Length, actual.Length, $"{name}.{nameof(actual.Length)}");

            for (var i = 0; i < expected.Length; i++)
                AssertEqual(expected[i], actual[i], $"{name}[{i}]", toString);
        }
        private static void AssertArrayEqual((ulong, ulong?)[] expected, ulong[] actual, string name, string format)
        {
            AssertArrayEqual(
                expected.Select(e => e.Item1).ToArray(),
                actual.Select((a, i) => a & (expected[i].Item2 ?? a)).ToArray(),
                name,
                ul => ul.ToString(format));
        }
    }
}
