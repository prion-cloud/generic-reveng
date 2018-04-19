using Superbr4in.SharpReverse.Api.PInvoke;

namespace Superbr4in.SharpReverse.Api.Factory
{
    public static class DebuggerFactory
    {
        public static IDebugger CreateNew(string fileName)
        {
            return new Debugger(fileName);
        }
    }
}
