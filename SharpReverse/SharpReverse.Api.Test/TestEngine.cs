using System;
using System.IO;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Superbr4in.SharpReverse.Api.Test
{
    public static class TestEngine
    {
        /// <summary>
        /// Placeholder for ignored strings.
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
                foreach (var expected in @case.Instructions)
                {
                    var actual = debugger.Debug();

                    Console.WriteLine($"0x{actual.Address}  {actual.Instruction}" +
                                      $"{(actual.Label == string.Empty ? null : $" ({actual.Label})")}");

                    AssertEqual(expected, actual);
                }
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

        private static void AssertEqual(IInstructionInfo expected, IInstructionInfo actual)
        {
            AssertEqual(expected.Id, actual.Id,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Id)}", i => $"0x{i:x}");

            AssertEqual(expected.Address, actual.Address,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Address)}");

            AssertArrayEqual(expected.Bytes, actual.Bytes,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Bytes)}", i => $"0x{i:x2}");

            AssertEqual(expected.Instruction, actual.Instruction,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Instruction)}");

            AssertEqual(expected.Label, actual.Label,
                $"{nameof(IInstructionInfo)}.{nameof(actual.Label)}");
        }

        private static void AssertEqual<T>(T expected, T actual, string description)
        {
            AssertEqual(expected, actual, description, t => t.ToString());
        }
        private static void AssertEqual<T>(T expected, T actual, string description, Func<T, string> toString)
        {
            if (expected is string str && str == PH)
                return;

            if (!Equals(expected, actual))
                AssertFail(toString(expected), toString(actual), description);
        }
        
        private static void AssertArrayEqual<T>(T[] expected, T[] actual, string name, Func<T, string> toString)
        {
            if (expected == null)
                return;

            AssertEqual(expected.Length, actual.Length, $"{name}.{nameof(actual.Length)}");

            for (var i = 0; i < expected.Length; i++)
                AssertEqual(expected[i], actual[i], $"{name}[{i}]", toString);
        }
    }
}
