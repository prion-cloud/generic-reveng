using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Superbr4in.SharpReverse.Api.Test
{
    public static class TestEngine
    {
        /// <summary>
        /// Placeholder for characters to be ignored in string comparison.
        /// </summary>
        public const string PH = "\uffff";

        public static void _Debugger_Debug<T>(DebuggerTestCase<T> @case)
        {
#if !WIN64
            if (@case.Amd64)
                AssertInconclusive("Expected platform configuration x64.");
#endif
            
            if (@case.Data is string path && !File.Exists(path))
                AssertInconclusive($"File \"{path}\" not found.");

            using (var debugger = @case.DebuggerConstructor(@case.Data))
            {
                foreach (var expected in @case.DebugResults)
                    AssertEqual(expected, (debugger.Debug(), debugger.InspectRegisters()));
            }
        }
        
        private static void AssertFail(string expected, string actual, string description)
        {
            throw new AssertFailedException($"{description} '{actual}' / '{expected}'\n");
        }
        private static void AssertInconclusive(string message)
        {
            throw new AssertInconclusiveException(message);
        }

        private static void AssertEqual((IInstructionInfo, IRegisterInfo[]) expected, (IInstructionInfo, IEnumerable<IRegisterInfo>) actual)
        {
            Console.WriteLine($"0x{actual.Item1.Address}  {actual.Item1.Instruction}");

            AssertEqual(expected.Item1.Id, actual.Item1.Id,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Id)}", i => $"0x{i:x}");

            AssertStringEqual(expected.Item1.Address, actual.Item1.Address,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Address)}");

            AssertArrayEqual(expected.Item1.Bytes, actual.Item1.Bytes,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Bytes)}", i => $"0x{i:x2}");

            AssertEqual(expected.Item1.Instruction, actual.Item1.Instruction,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Item1.Instruction)}");

            var exp = expected.Item2;
            var act = actual.Item2.ToArray();

            if (exp.Length != act.Length)
                Assert.Fail("Length"); // TODO

            for (var i = 0; i < exp.Length; i++)
            {
                var e = exp[i];
                var a = act[i];

                AssertEqual(e.Name, a.Name,
                    $"{nameof(IRegisterInfo)}[{i}].{nameof(e.Name)}");
                AssertStringEqual(e.Value, a.Value,
                    $"{nameof(IRegisterInfo)}[{i}].{nameof(e.Value)}");
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string description)
        {
            AssertEqual(expected, actual, description, t => t.ToString());
        }
        private static void AssertEqual<T>(T expected, T actual, string description, Func<T, string> toString)
        {
            if (!Equals(expected, actual))
                AssertFail(toString(expected), toString(actual), description);
        }
        
        private static void AssertArrayEqual<T>(T[] expected, T[] actual, string name, Func<T, string> toString)
        {
            AssertEqual(expected.Length, actual.Length, $"{name}.{nameof(actual.Length)}");

            for (var i = 0; i < expected.Length; i++)
                AssertEqual(expected[i], actual[i], $"{name}[{i}]", toString);
        }

        private static void AssertStringEqual(string expected, string actual, string name)
        {
            if (expected == PH)
                return;

            AssertEqual(expected.Length, actual.Length, $"{name}.{nameof(actual.Length)}");

            AssertEqual(expected, actual, name);
        }
    }
}
