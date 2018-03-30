using System.Runtime.InteropServices;

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct RegisterInfo : IRegisterInfo
    {
        #region Fields
        
        // ReSharper disable All
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
        public ulong[] Registers_;

        // ReSharper restore All

        #endregion

        public ulong[] Registers => Registers_;
    }
}
