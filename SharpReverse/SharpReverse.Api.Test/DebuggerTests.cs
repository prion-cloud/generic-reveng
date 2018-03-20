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
            using (var debugger = new Debugger(@case.FileName))
            {
                foreach (var debug in @case.Debugs)
                    Assert.That.DebugEqual(debug, (debugger.Debug32(), debugger.GetRegisterState32()));
            }
        }
    }
}
