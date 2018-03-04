using System.Collections.Generic;

namespace AutoReverse.Api
{
    public static class Disassembler
    {
        public static IEnumerable<(ulong, byte[], ushort, string, string)> Disassemble_x86_32(byte[] bytes)
        {
            return Disassemble(PInvoke.Architecture.X86, PInvoke.Mode.B32, bytes);
        }
        public static IEnumerable<(ulong, byte[], ushort, string, string)> Disassemble_x86_64(byte[] bytes)
        {
            return Disassemble(PInvoke.Architecture.X86, PInvoke.Mode.B64, bytes);
        }

        private static IEnumerable<(ulong, byte[], ushort, string, string)> Disassemble(PInvoke.Architecture architecture, PInvoke.Mode mode, byte[] bytes)
        {
            var dis = PInvoke.disassembler_open(architecture, mode, bytes, bytes.Length);

            int result;

            do
            {
                result = PInvoke.disassemble(dis, out var instr);
                yield return (instr.Address, instr.Bytes, instr.Size, instr.Mnemonic, instr.OpStr);
            }
            while (result == 0);

            PInvoke.disassembler_close(dis);
        }
    }
}
