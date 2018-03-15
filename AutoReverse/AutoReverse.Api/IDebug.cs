namespace AutoReverse.Api
{
    public interface IDebug
    {
        int Id { get; }

        int Address { get; }

        byte[] Bytes { get; }

        string Instruction { get; }

        int[] Registers { get; }
    }
}
