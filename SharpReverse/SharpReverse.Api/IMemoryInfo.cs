namespace Superbr4in.SharpReverse.Api
{
    public interface IMemoryInfo
    {
        ulong Begin { get; }
        ulong Size { get; }

        uint Permissions { get; }
    }
}
