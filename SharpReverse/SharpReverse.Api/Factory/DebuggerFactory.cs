using Superbr4in.SharpReverse.Api.PInvoke;

namespace Superbr4in.SharpReverse.Api.Factory
{
    public static class DebuggerFactory
    {
        public static IDebugger CreateNew(byte[] bytes, bool amd64)
        {
            return new Debugger(bytes, amd64);
        }
        public static IDebugger CreateNew(string fileName)
        {
            return new Debugger(fileName);
        }
    }
}
