using System;

namespace SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        private readonly IntPtr _handle;

        public Debugger(string fileName)
        {
            _handle = PInvoke.open_file(fileName);
        }
        public Debugger(byte[] bytes)
        {
            _handle = PInvoke.open_bytes(bytes, Convert.ToUInt64(bytes.Length));
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
            PInvoke.close(_handle);
        }

        public Instruction32 Debug32()
        {
            PInvoke.debug_32(_handle, out var instruction);
            return instruction;
        }

        public RegisterState32 GetRegisterState32()
        {
            PInvoke.get_register_state_32(_handle, out var registerState);
            return registerState;
        }
    }
}
