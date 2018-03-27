// ReSharper disable All

using System;
using System.Runtime.InteropServices;

using SharpReverse.Api.PInvoke.Struct;

namespace SharpReverse.Api.PInvoke
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
        public static extern int debugger_load_file(out IntPtr handle, out ulong scale, string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_unload(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_step(IntPtr handle, out InstructionInfo ins_info);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int debugger_reg(IntPtr handle, out RegisterInfo reg_info);
    }
}

namespace SharpReverse.Api.PInvoke.Struct
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
}
