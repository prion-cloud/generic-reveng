using System;
using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    // ReSharper disable All

    internal static class PInvoke
    {
        public const string DLL_NAME = "AutoReverse.LibWrapper.dll";

        [DllImport(DLL_NAME)] public static extern IntPtr open(string fileName);
        [DllImport(DLL_NAME)] public static extern IntPtr close(IntPtr handle);
        [DllImport(DLL_NAME)] public static extern void debug_32(IntPtr handle, out Debug32 debug);
    }

    public partial struct Debug32
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

        internal uint Eax_, Ebx_, Ecx_, Edx_;
        internal uint Esp_, Ebp_;
        internal uint Esi_, Edi_;
        internal uint Eip_;
    }

    //#pragma warning disable 649 TODO
    //#pragma warning restore 649
}
