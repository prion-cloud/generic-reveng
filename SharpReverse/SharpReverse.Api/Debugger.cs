using System;

using SharpReverse.Api.PInvoke;

namespace SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        private readonly IntPtr _handle;

        public TargetMachine Target { get; }
        
        public Debugger(byte[] bytes)
        {
            Target = Interop.Open(out _handle, bytes, bytes.Length);
        }
        public Debugger(string fileName)
        {
            Target = Interop.OpenFile(out _handle, fileName);
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
            Interop.Close(_handle);
        }

        public IInstructionInfo Debug()
        {
            Interop.Debug(_handle, out var instruction);
            return instruction;
        }

        public IRegisterInfo InspectRegisters()
        {
            Interop.InspectRegisters(_handle, out var registerState);
            return registerState;
        }
    }
}
