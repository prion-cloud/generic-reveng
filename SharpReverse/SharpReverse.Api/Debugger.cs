using System;

using SharpReverse.Api.PInvoke;

namespace SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        private readonly IntPtr _handle;

        public bool Is64BitMode
        {
            get
            {
                if (_handle == IntPtr.Zero)
                    throw new InvalidOperationException();

                return Interop.targets_64(_handle);
            }
        }

        public Debugger(byte[] bytes)
        {
            Interop.debugger_open(out _handle, bytes, bytes.Length);
        }
        public Debugger(string fileName)
        {
            Interop.debugger_open_file(out _handle, fileName);
        }

        ~Debugger()
        {
            ReleaseUnmanagedResources();
        }

        public void Dispose()
        {
            // TODO: Verify dispose pattern.
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        private void ReleaseUnmanagedResources()
        {
            Interop.debugger_close(_handle);
        }

        public IInstructionInfo Debug()
        {
            Interop.debug(_handle, out var instruction);
            return instruction;
        }

        public IRegisterInfo InspectRegisters()
        {
            Interop.inspect_registers(_handle, out var registerState);
            return registerState;
        }
    }
}
