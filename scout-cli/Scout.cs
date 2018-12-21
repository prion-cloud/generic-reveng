using System;
using System.Runtime.InteropServices;

public static class Scout
{
    public struct Instruction
    {
        public uint Id;

        public ulong Address;

        public ushort Size;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Bytes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Mnemonic;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 160)]
        public string OpStr;

        public IntPtr Detail;
    }

    private const string SCOUT_API_NAME = "../build/scout-api/libscout-api.so";

    [DllImport(SCOUT_API_NAME, EntryPoint = "create_control_flow")]
    public static extern IntPtr CreateControlFlow(string fileName);

    [DllImport(SCOUT_API_NAME, EntryPoint = "release_control_flow_handle")]
    public static extern void ReleaseControlFlowHandle(IntPtr controlFlowHandle);

    [DllImport(SCOUT_API_NAME, EntryPoint = "get_root_block")]
    public static extern IntPtr GetRootBlock(IntPtr controlFlowHandle);

    [DllImport(SCOUT_API_NAME, EntryPoint = "count_block_successors")]
    public static extern int CountBlockSuccessors(IntPtr blockHandle);
    [DllImport(SCOUT_API_NAME, EntryPoint = "get_block_successor")]
    public static extern IntPtr GetBlockSuccessor(IntPtr blockHandle, int index);

    [DllImport(SCOUT_API_NAME, EntryPoint = "count_block_instructions")]
    public static extern int CountBlockInstructions(IntPtr blockHandle);
    [DllImport(SCOUT_API_NAME, EntryPoint = "disassemble_block_instruction")]
    public static extern void DisassembleBlockInstruction(IntPtr blockHandle, int index, out Instruction instruction);
}
