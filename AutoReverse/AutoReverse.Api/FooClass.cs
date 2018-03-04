using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    public static class FooClass
    {
        private struct Instruction
        {
            public uint Id;

            public ulong Address;

            public ushort Size;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = UnmanagedType.U8)]
            public byte[] Bytes;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string Mnemonic;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
            public string OpStr;
        }

        [DllImport("AutoReverse.LibWrapper.dll")]
        private static extern IntPtr create_disassembler(byte[] bytes);

        [DllImport("AutoReverse.LibWrapper.dll")]
        private static extern void seek(ulong offset);

        [DllImport("AutoReverse.LibWrapper.dll")]
        private static extern int disassemble(IntPtr disassembler, out Instruction instruction);

        public static int Foo()
        {
            var dis = create_disassembler(new byte[] { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 });

            for (var i = 0; i < 2; i++)
            {
                var result = disassemble(dis, out var instr);

                if (result != 0)
                    return result;
                
                var bytesStr = $"{instr.Bytes[0]:X2}";
                for (var j = 1; j < instr.Bytes.Length; j++)
                {
                    var b = instr.Bytes[j];

                    if (b == 0xCD)
                        break;

                    bytesStr += $" {b:X2}";
                }

                Console.WriteLine($"{instr.Address:X8} :\t{instr.Mnemonic} {instr.OpStr}\t({bytesStr})");
            }

            return 0;
        }
    }
}
