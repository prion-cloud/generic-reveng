using System.Runtime.InteropServices;

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct MemoryInfo : IMemoryInfo
    {
        #region Fields
        
        // ReSharper disable All
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Begin_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Size_;
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4)]
        public string Permissions_;

        // ReSharper restore All

        #endregion

        public string Begin => Begin_;
        public string Size => Size_;

        public string Permissions => Permissions_;
    }
}
