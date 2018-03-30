using Microsoft.VisualStudio.TestTools.UnitTesting;

using Superbr4in.SharpReverse.Api.PInvoke;

namespace Superbr4in.SharpReverse.Api.Test
{
    [TestClass]
    [DeploymentItem(Debugger.DLL_NAME)]
    [DeploymentItem(TestDeploy.FOLDER)]
    public class DebuggerTest
    {
        [TestMethod] public void Debug_Case32_Bytes1()
        {
            TestEngine._Debugger_Debug(DebuggerTestCase.GetTestCase32_Bytes1());
        }
        [TestMethod] public void Debug_Case32_File1()
        {
            TestEngine._Debugger_Debug(DebuggerTestCase.GetTestCase32_File1());
        }
        
        [TestMethod] public void Debug_Case64_Bytes1()
        {
            TestEngine._Debugger_Debug(DebuggerTestCase.GetTestCase64_Bytes1());
        }
        [TestMethod] public void Debug_Case64_File1()
        {
            TestEngine._Debugger_Debug(DebuggerTestCase.GetTestCase64_File1());
        }
    }
}
