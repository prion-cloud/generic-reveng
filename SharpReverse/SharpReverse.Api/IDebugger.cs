using System;
using System.Collections.Generic;

namespace Superbr4in.SharpReverse.Api
{
    public interface IDebugger : IDisposable
    {
        IInstructionInfo Debug();

        IEnumerable<IRegisterInfo> InspectRegisters();
        IEnumerable<IMemoryInfo> InspectMemory();
    }
}
