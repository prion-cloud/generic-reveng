using System;
using System.Collections.Generic;

namespace Superbr4in.SharpReverse.Api
{
    public interface IDebugger : IDisposable
    {
        bool Amd64 { get; }

        IInstructionInfo Debug();

        IEnumerable<IRegisterInfo> InspectRegisters();
        IEnumerable<IMemoryInfo> InspectMemory();
    }
}
