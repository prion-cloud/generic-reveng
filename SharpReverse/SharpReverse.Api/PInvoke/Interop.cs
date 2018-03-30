// ReSharper disable All

using System;
using System.Runtime.InteropServices;

using Superbr4in.SharpReverse.Api.PInvoke.Struct;

namespace Superbr4in.SharpReverse.Api.PInvoke
{
    internal static class Interop
    {
        public const string DLL_NAME =
#if WIN64
            "DebugEngine64.dll";
#else
            "DebugEngine32.dll";
#endif

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_load(out IntPtr handle, ulong scale, byte[] bytes, int size);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_load_file(out IntPtr handle, out ulong scale, string file_name);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_unload(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_ins(IntPtr handle, out InstructionInfo ins_info);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_reg(IntPtr handle, out RegisterInfo reg_info);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_mem(IntPtr handle, out MemoryInfo[] mem_infos);
    }
}

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal partial struct InstructionInfo
    {
        public uint Id_;

        public ulong Address_;

        public ushort Size_;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Bytes_;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Mnemonic_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        public string Operands_;
    }

    internal partial struct RegisterInfo
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
        public ulong[] Registers_;
    }

    internal partial struct MemoryInfo
    {
        public ulong Begin_;
        public ulong Size_;

        public uint Permissions_;
    }
}
