using System.Runtime.InteropServices;

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct RegisterInfo : IRegisterInfo
    {
        #region Fields
        
        // ReSharper disable All
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4)]
        public string Name_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Value_;

        // ReSharper restore All

        #endregion

        public string Name => Name_;
        public string Value => Value_;
    }
}
