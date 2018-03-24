using SharpReverse.Api.Interface;

namespace SharpReverse.Api
{
    public partial struct RegisterInfo32 : IRegisterInfo
    {
        public uint[] Registers => new[] { Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_ };
    }
}
