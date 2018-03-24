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

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr open_file(
            string fileName);
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr open_bytes(
            byte[] bytes, ulong count);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void close(
            IntPtr handle);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void debug_32(
            IntPtr handle,
            out Instruction32 instruction);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void get_register_state_32(
            IntPtr handle,
            out RegisterState32 register_state);
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

    public partial struct RegisterState32
    {
        internal uint Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_;
    }

    //#pragma warning disable 649 TODO
    //#pragma warning restore 649
}
