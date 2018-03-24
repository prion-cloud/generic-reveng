using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SharpReverse.Api.Test
{
    [TestClass]
    [DeploymentItem(PInvoke.DLL_NAME)]
    [DeploymentItem(Deploy.FOLDER, Deploy.FOLDER)]
    public class DebuggerTest32
    {
        [TestMethod] public void Debug_Case1()
        {
            TestDebug(DebuggerTestCase.GetTestCase1());
        }
        [TestMethod] public void Debug_Case2()
        {
            TestDebug(DebuggerTestCase.GetTestCase2());
        }

        private static void TestDebug(DebuggerTestCase @case)
        {
            using (@case.Debugger)
            {
                foreach (var debug in @case.DebugInfos)
                {
                    Console.WriteLine($"0x{debug.Item1.Address:x8} | {debug.Item1.Instruction}");
                    DebuggerAssert.Equal(debug, (@case.Debugger.Debug(), @case.Debugger.GetRegisterState()));
                }
            }
        }
    }
}
