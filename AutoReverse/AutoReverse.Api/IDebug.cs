namespace AutoReverse.Api
{
    public interface IDebug
    {
        uint Id { get; }

        uint Address { get; }

        byte[] Bytes { get; }

        string Instruction { get; }

        uint[] Registers { get; }
    }
}
