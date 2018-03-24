using System;

using SharpReverse.Api.Interface;

namespace SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        private readonly IntPtr _handle;
        
        public Debugger(byte[] bytes)
        {
            _handle = PInvoke.Open(bytes, Convert.ToUInt64(bytes.Length));
        }
        public Debugger(string fileName)
        {
            _handle = PInvoke.OpenFile(fileName);
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
            PInvoke.Close(_handle);
        }

        public IInstructionInfo Debug()
        {
            PInvoke.Debug(_handle, out var instruction);
            return instruction;
        }

        public IRegisterInfo GetRegisterState()
        {
            PInvoke.GetRegisterState(_handle, out var registerState);
            return registerState;
        }
    }
}
