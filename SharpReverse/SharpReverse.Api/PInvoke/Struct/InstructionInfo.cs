using System.Linq;

namespace SharpReverse.Api.PInvoke.Struct
{
    internal partial struct InstructionInfo : IInstructionInfo
    {
        public uint Id => Id_;

        public ulong Address => Address_;

        public byte[] Bytes => Bytes_.Take(Size_).ToArray();

        public string Instruction => $"{Mnemonic_}{(Operands_ == string.Empty ? null : $" {Operands_}")}";
    }
}
