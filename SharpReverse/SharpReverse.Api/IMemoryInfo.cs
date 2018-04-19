namespace Superbr4in.SharpReverse.Api
{
    public interface IMemoryInfo
    {
        string Address { get; }
        string Size { get; }

        string Owner { get; }
        string Description { get; }

        string Access { get; }
    }
}
