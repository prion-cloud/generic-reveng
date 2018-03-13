using System;
using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    internal static class PInvoke
    {
        public const string DLL_NAME = "AutoReverse.LibWrapper.dll";

        [DllImport(DLL_NAME)] public static extern IntPtr disassembler_open(string fileName);
        [DllImport(DLL_NAME)] public static extern IntPtr disassembler_close(IntPtr disassembler);
        [DllImport(DLL_NAME)] public static extern int disassemble(IntPtr disassembler, out Instruction instruction);

        public struct Instruction
        {
            public uint Id;
            public ulong Address;
            public ushort Size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Bytes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string Mnemonic;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
            public string OpStr;
        }
    }
}
