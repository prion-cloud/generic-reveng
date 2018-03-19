using System.Collections.Generic;

namespace SharpReverse.Api
{
    public interface IDebug
    {
        uint Id { get; }

        uint Address { get; }

        IEnumerable<byte> Bytes { get; }

        string Instruction { get; }

        uint[] Registers { get; }
    }
}
