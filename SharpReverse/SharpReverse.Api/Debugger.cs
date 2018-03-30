using System;

using Superbr4in.SharpReverse.Api.PInvoke;

namespace Superbr4in.SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        #region Fields

        private readonly IntPtr _handle;
        private readonly ulong _scale;

        #endregion

        #region Properties

        public bool Amd64 => _scale == ulong.MaxValue;

        #endregion

        public Debugger(byte[] bytes)
        {
            throw new NotImplementedException();
        }
        public Debugger(string fileName)
        {
            Interop.debugger_load_file(out _handle, out _scale, fileName);
        }

        ~Debugger()
        {
            ReleaseUnmanagedResources();
        }

        public void Dispose()
        {
            // TODO: Verify this dispose pattern.
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        private void ReleaseUnmanagedResources()
        {
            Interop.debugger_unload(_handle);
        }

        public IInstructionInfo Debug()
        {
            Interop.debugger_ins(_handle, out var instruction);
            return instruction;
        }

        public IRegisterInfo InspectRegisters()
        {
            Interop.debugger_reg(_handle, out var registerState);
            return registerState;
        }
    }
}
