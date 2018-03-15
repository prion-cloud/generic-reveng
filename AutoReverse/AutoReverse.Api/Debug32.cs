using System.Linq;

namespace AutoReverse.Api
{
    public partial struct Debug32 : IDebug
    {
        public int Id => Id_;

        public int Address => Address_;

        public byte[] Bytes => Bytes_.Take(Size_).ToArray();

        public string Instruction => $"{Mnemonic_} {Operands_}";

        public int[] Registers => new[]
        {
            Eax_, Ebx_, Ecx_, Edx_,
            Esp_, Ebp_,
            Esi_, Edi_,
            Eip_
        };
    }
}
