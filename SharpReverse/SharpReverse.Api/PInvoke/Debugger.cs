using System;
using System.Runtime.InteropServices;

using Superbr4in.SharpReverse.Api.PInvoke.Struct;

namespace Superbr4in.SharpReverse.Api.PInvoke
{
    internal unsafe class Debugger : IDebugger
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

        private readonly void* _handle;
        private readonly ulong _scale;

        #endregion

        #region Properties

        public bool Amd64 => _scale == ulong.MaxValue;

        #endregion

        public Debugger(byte[] bytes, bool amd64)
        {
            throw new NotImplementedException();
        }
        public Debugger(string fileName)
        {
            LoadFile(out _handle, out _scale, fileName);
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
            Ins(_handle, out var ins);
            return ins;
        }

        public IRegisterInfo InspectRegisters()
        {
            Reg(_handle, out var reg);
            return reg;
        }

        public IMemoryInfo[] InspectMemory()
        {
            Mem(_handle, out var mem, out var count);
            
            var result = new IMemoryInfo[count];
            
            for (var i = 0; i < count; i++)
                result[i] = mem[i];

            return result;
        }
        
        #region DllImports
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_load")]
        private static extern int Load(out void* handle, ulong scale, byte[] bytes, int size);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_load_file")]
        private static extern int LoadFile(out void* handle, out ulong scale, string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_unload")]
        private static extern int Unload(void* handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_ins")]
        private static extern int Ins(void* handle, out InstructionInfo info);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_reg")]
        private static extern int Reg(void* handle, out RegisterInfo info);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debugger_mem")]
        private static extern int Mem(void* handle, out MemoryInfo* info, out int count);

        #endregion
    }
}
