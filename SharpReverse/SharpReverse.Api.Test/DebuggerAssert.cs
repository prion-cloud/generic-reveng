using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpReverse.Api.Interface;

namespace SharpReverse.Api.Test
{
    public static class DebuggerAssert
    {
        public static void Equal((IInstruction, IRegisterState) expected, (IInstruction, IRegisterState) actual)
        {
            Assert.AreEqual(expected.Item1.Id, actual.Item1.Id, nameof(actual.Item1.Id));
            Assert.AreEqual(expected.Item1.Address, actual.Item1.Address, nameof(actual.Item1.Address));
            Assert.IsTrue(actual.Item1.Bytes.SequenceEqual(expected.Item1.Bytes), nameof(actual.Item1.Bytes));
            Assert.AreEqual(expected.Item1.Instruction, actual.Item1.Instruction, nameof(actual.Item1.Instruction));

            Assert.IsTrue(actual.Item2.Registers.SequenceEqual(expected.Item2.Registers), nameof(actual.Item2.Registers));
        }
    }
}
