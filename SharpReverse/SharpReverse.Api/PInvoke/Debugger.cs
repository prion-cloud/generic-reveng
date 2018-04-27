using System;
using System.Runtime.InteropServices;

using Superbr4in.SharpReverse.Api.PInvoke.Struct;

namespace Superbr4in.SharpReverse.Api.PInvoke
{
    internal class Debugger : IDebugger
    {
        #region Constants

        public const string DLL_NAME =
#if WIN64
            "DebugEngine64.dll";
#else
            "DebugEngine32.dll";
#endif

        #endregion
        
        #region Fields

        private readonly IntPtr _handle;

        #endregion

        public Debugger(string fileName)
        {
            if (LoadFile(out _handle, fileName) != 0)
                throw new InvalidOperationException("Loading failed.");
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
            Unload(_handle);
        }

        public IInstructionInfo Debug()
        {
            if (Ins(_handle, out var ins) != 0)
                throw new InvalidOperationException("Tried to debug invalid instruction.");
            return ins;
        }
        
        #region DllImports
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_load_file")]
        private static extern int LoadFile(out IntPtr handle, string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_unload")]
        private static extern int Unload(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_ins")]
        private static extern int Ins(IntPtr handle, out InstructionInfo ins);

        #endregion
    }
}
