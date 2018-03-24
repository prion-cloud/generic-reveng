using System;
using System.Runtime.InteropServices;

namespace SharpReverse.Api
{
    // ReSharper disable All

    internal static class PInvoke
    {
        public const string DLL_NAME =
#if WIN64
            "DebugEngine64.dll";
#else
            "DebugEngine32.dll";
#endif
        
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "open")]
        public static extern IntPtr Open(byte[] bytes, ulong count);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "open_file")]
        public static extern IntPtr OpenFile(string fileName);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "close")]
        public static extern void Close(IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "debug")]
        public static extern void Debug(IntPtr handle, out Instruction32 instruction);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "get_register_state")]
        public static extern void GetRegisterState(IntPtr handle, out RegisterInfo32 register_state);
    }

    public partial struct Instruction32
    {
        internal uint Id_;

        internal uint Address_;

        internal ushort Size_;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] Bytes_;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        internal string Mnemonic_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        internal string Operands_;
    }

    public partial struct RegisterInfo32
    {
        internal uint Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_;
    }

    //#pragma warning disable 649 TODO
    //#pragma warning restore 649
}
