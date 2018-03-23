using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpReverse.Api.Interface;

namespace SharpReverse.Api.Test
{
    [TestClass]
    [DeploymentItem(PInvoke.DLL_NAME)]
    [DeploymentItem(Deploy.FOLDER, Deploy.FOLDER)]
    public class DebuggerTests
    {
        [TestMethod] public void Debug32_Case1()
        {
            TestDebug32(DebuggerTestCase.GetTestCase1());
        }
        [TestMethod] public void Debug32_Case2()
        {
            TestDebug32(DebuggerTestCase.GetTestCase2());
        }

        private static void TestDebug32(DebuggerTestCase @case)
        {
            using (@case.Debugger)
            {
                foreach (var debug in @case.Debugs)
                    AssertDebugEqual(debug, (@case.Debugger.Debug32(), @case.Debugger.GetRegisterState32()));
            }
        }

        private static void AssertDebugEqual((IInstruction, IRegisterState) expected, (IInstruction, IRegisterState) actual)
        {
            Assert.AreEqual(expected.Item1.Id, actual.Item1.Id);
            Assert.AreEqual(expected.Item1.Address, actual.Item1.Address);
            Assert.IsTrue(actual.Item1.Bytes.SequenceEqual(expected.Item1.Bytes));
            Assert.AreEqual(expected.Item1.Instruction, actual.Item1.Instruction);

            Assert.IsTrue(actual.Item2.Registers.SequenceEqual(expected.Item2.Registers));
        }
    }
}
