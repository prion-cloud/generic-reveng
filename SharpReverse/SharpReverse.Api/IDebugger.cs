using System;

namespace Superbr4in.SharpReverse.Api
{
    public interface IDebugger : IDisposable
    {
        bool Amd64 { get; }

        IInstructionInfo Debug();

        IRegisterInfo InspectRegisters();
        IMemoryInfo InspectMemory();
    }
}
