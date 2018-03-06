using System.Collections.Generic;

namespace AutoReverse.Api
{
    public static class Disassembler
    {
        public static IEnumerable<(ulong, byte[], ushort, string, string)> Disassemble_x86_32(string fileName)
        {
            return Disassemble(fileName);
        }

        private static IEnumerable<(ulong, byte[], ushort, string, string)> Disassemble(string fileName)
        {
            var dis = PInvoke.disassembler_open(fileName);

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
