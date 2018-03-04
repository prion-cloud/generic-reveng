using System;
using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    public static class FooClass
    {
        private struct FooStruct
        {
            public uint id;

            public ulong address;

            public ushort size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = UnmanagedType.U8)]
            public byte[] bytes;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string mnemonic;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
            public string opStr;

            public IntPtr detail;
        }

        [DllImport("AutoReverse.LibWrapper.dll")]
        private static extern int disasm(byte[] bytes, ref FooStruct s);

        public static int Foo()
        {
            var s = new FooStruct();

            var result = disasm(
                new byte[] { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 }, ref s);

            if (result == 0)
                Console.WriteLine(s.mnemonic);

            return result;
        }
    }
}
