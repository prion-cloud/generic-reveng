using System.Collections.Generic;
using System.Linq;

namespace AutoReverse.Api
{
    public partial struct Debug32 : IDebug
    {
        public uint Id => Id_;

        public uint Address => Address_;

        public IEnumerable<byte> Bytes => Bytes_.Take(Size_);

        public string Instruction => $"{Mnemonic_} {Operands_}";

        public uint[] Registers => new[]
        {
            Eax_, Ebx_, Ecx_, Edx_,
            Esp_, Ebp_,
            Esi_, Edi_,
            Eip_
        };
    }
}
