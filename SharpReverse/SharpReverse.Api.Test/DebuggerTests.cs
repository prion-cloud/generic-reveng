using Microsoft.VisualStudio.TestTools.UnitTesting;

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
                    Assert.That.DebugEqual(debug, (@case.Debugger.Debug32(), @case.Debugger.GetRegisterState32()));
            }
        }
    }
}
