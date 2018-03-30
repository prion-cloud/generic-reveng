namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct MemoryInfo : IMemoryInfo
    {
        #region Fields
        
        // ReSharper disable All

        public ulong Begin_;
        public ulong Size_;

        public uint Permissions_;

        // ReSharper restore All

        #endregion

        public ulong Begin => Begin_;
        public ulong Size => Size_;

        public uint Permissions => Permissions_;
    }
}
