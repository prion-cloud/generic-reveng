using System.Collections.Generic;
using System.Linq;

using SharpReverse.Api.Interface;

// ReSharper disable once CheckNamespace
namespace SharpReverse.Api
{
    public partial struct Instruction32 : IInstruction
    {
        public uint Id => Id_;

        public uint Address => Address_;

        public IEnumerable<byte> Bytes => Bytes_.Take(Size_);

        public string Instruction => $"{Mnemonic_}{(Operands_ == string.Empty ? null : $" {Operands_}")}";
    }
}
