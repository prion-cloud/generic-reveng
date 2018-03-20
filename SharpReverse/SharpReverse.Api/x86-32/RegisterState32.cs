using SharpReverse.Api.Interface;

// ReSharper disable once CheckNamespace
namespace SharpReverse.Api
{
    public partial struct RegisterState32 : IRegisterState
    {
        public uint[] Registers => new[] { Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_ };
    }
}
