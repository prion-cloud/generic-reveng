namespace Superbr4in.SharpReverse.Api
{
    public interface IInstructionInfo
    {
        uint Id { get; }

        string Address { get; }

        byte[] Bytes { get; }

        string Instruction { get; }
    }
}
