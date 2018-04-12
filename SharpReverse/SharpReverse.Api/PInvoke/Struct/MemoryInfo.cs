using System.Runtime.InteropServices;

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct MemoryInfo : IMemoryInfo
    {
        #region Fields
        
        // ReSharper disable All
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Address_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Size_;
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Section_;
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4)]
        public string Access_;

        // ReSharper restore All

        #endregion

        public string Address => Address_;
        public string Size => Size_;

        public string Section => Section_;

        public string Access => Access_;
    }
}
