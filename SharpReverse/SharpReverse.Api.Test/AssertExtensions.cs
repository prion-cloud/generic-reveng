using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpReverse.Api.Test
{
    public static class AssertExtensions
    {
        // ReSharper disable once UnusedParameter.Global
        public static void DebugEqual(this Assert assert, IDebug expected, IDebug actual)
        {
            Assert.AreEqual(expected.Id, actual.Id);
            Assert.AreEqual(expected.Address, actual.Address);
            Assert.IsTrue(actual.Bytes.SequenceEqual(expected.Bytes));
            Assert.AreEqual(expected.Instruction, actual.Instruction);
            Assert.IsTrue(actual.Registers.SequenceEqual(expected.Registers));
        }
    }
}
