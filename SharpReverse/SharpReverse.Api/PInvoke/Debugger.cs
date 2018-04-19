using System;
using System.Collections.Generic;
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

        public IEnumerable<IRegisterInfo> InspectRegisters()
        {
            while (Reg(_handle, out var reg) == 0)
                yield return reg;
        }

        public IEnumerable<IMemoryInfo> InspectMemory()
        {
            while (Mem(_handle, out var mem) == 0)
                yield return mem;
        }
        
        #region DllImports
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_load_file")]
        private static extern int LoadFile(out IntPtr handle, string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_unload")]
        private static extern int Unload(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_ins")]
        private static extern int Ins(IntPtr handle, out InstructionInfo ins);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_reg")]
        private static extern int Reg(IntPtr handle, out RegisterInfo reg);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_mem")]
        private static extern int Mem(IntPtr handle, out MemoryInfo mem);

        #endregion
    }
}
