using System.Linq;
using System.Runtime.InteropServices;

namespace Superbr4in.SharpReverse.Api.PInvoke.Struct
{
    internal struct InstructionInfo : IInstructionInfo
    {
        #region Fields

        // ReSharper disable All

        public uint Id_;
        
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 19)]
        public string Address_;

        public ushort Size_;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Bytes_;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Mnemonic_;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        public string Operands_;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string Comment_;
        
        // ReSharper restore All

        #endregion

        public uint Id => Id_;

        public string Address => Address_;

        public byte[] Bytes => Bytes_.Take(Size_).ToArray();

        public string Instruction => $"{Mnemonic_}{(Operands_ == string.Empty ? null : $" {Operands_}")}";

        public string Comment => Comment_;
    }
}
