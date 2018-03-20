using System.Collections.Generic;

namespace SharpReverse.Api.Interface
{
    public interface IInstruction
    {
        uint Id { get; }

        uint Address { get; }

        IEnumerable<byte> Bytes { get; }

        string Instruction { get; }
    }
}
