namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal partial struct MemoryInfo : IMemoryInfo
    {
        public ulong Begin => Begin_;
        public ulong Size => Size_;

        public uint Permissions => Permissions_;
    }
}
