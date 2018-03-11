using System.Collections.Generic;
using System.Linq;

namespace AutoReverse.Api
{
    public static class Disassembler
    {
        public static IEnumerable<AsmInstruction> Disassemble_x86_32(string fileName)
        {
            return Disassemble(fileName);
        }

        private static IEnumerable<AsmInstruction> Disassemble(string fileName)
        {
            var dis = PInvoke.disassembler_open(fileName);

            int result;
            
            do
            {
                result = PInvoke.disassemble(dis, out var instr);
                yield return new AsmInstruction(instr.Address, instr.Bytes.Take(instr.Size).ToArray(), instr.Mnemonic,
                    instr.OpStr);
            }
            while (result == 0);

            PInvoke.disassembler_close(dis);
        }
    }
}
