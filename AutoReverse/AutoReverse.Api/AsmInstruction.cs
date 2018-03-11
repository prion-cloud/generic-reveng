namespace AutoReverse.Api
{
    public struct AsmInstruction
    {
        public readonly ulong Address;
        public readonly byte[] Bytes;
        public readonly string Mnemonic;
        public readonly string Operands;

        internal AsmInstruction(ulong address, byte[] bytes, string mnemonic, string operands)
        {
            Address = address;
            Bytes = bytes;
            Mnemonic = mnemonic;
            Operands = operands;
        }
    }
}
