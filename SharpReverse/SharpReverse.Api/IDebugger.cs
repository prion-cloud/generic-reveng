using System;

namespace Superbr4in.SharpReverse.Api
{
    public interface IDebugger : IDisposable
    {
        IInstructionInfo Debug();
    }
}
