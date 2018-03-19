using System;

namespace SharpReverse.Api
{
    public class Debugger : IDisposable
    {
        private readonly IntPtr _handle;

        public Debugger(string fileName)
        {
            _handle = PInvoke.open(fileName);
        }

        ~Debugger()
        {
            ReleaseUnmanagedResources();
        }

        public Debug32 Debug32()
        {
            PInvoke.debug_32(_handle, out var debug);
            return debug;
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
    }
}
