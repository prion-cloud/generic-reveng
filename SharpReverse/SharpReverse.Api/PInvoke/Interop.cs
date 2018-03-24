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

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "open")]
        public static extern TargetMachine Open(out IntPtr handle, byte[] bytes, int size);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "open_file")]
        public static extern TargetMachine OpenFile(out IntPtr handle, string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "close")]
        public static extern void Close(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debug")]
        public static extern void Debug(IntPtr handle, out InstructionInfo instructionInfo);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "inspect_registers")]
        public static extern void InspectRegisters(IntPtr handle, out RegisterInfo registerInfo);
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
        public ulong Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_;
    }
}
