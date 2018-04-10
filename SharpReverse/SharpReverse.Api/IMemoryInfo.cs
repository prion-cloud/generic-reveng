namespace Superbr4in.SharpReverse.Api
{
    public interface IMemoryInfo
    {
        string Address { get; }
        string Size { get; }

        string Section { get; }

        string Access { get; }
    }
}
