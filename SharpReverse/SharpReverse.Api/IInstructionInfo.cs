namespace SharpReverse.Api
{
    public interface IInstructionInfo
    {
        uint Id { get; }

        ulong Address { get; }

        byte[] Bytes { get; }

        string Instruction { get; }
    }
}
