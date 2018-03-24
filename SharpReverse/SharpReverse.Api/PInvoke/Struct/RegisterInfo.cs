namespace SharpReverse.Api.PInvoke.Struct
{
    internal partial struct RegisterInfo : IRegisterInfo
    {
        public ulong[] Registers => new[] { Eax_, Ebx_, Ecx_, Edx_, Esp_, Ebp_, Esi_, Edi_, Eip_ };
    }
}
