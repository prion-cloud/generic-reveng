namespace AutoReverse.Api.Test
{
    public class DebuggerTestCase
    {
        #region Properties

        public string FileName { get; }

        public IDebug[] Debugs { get; }

        #endregion

        private DebuggerTestCase(string fileName, IDebug[] debugs)
        {
            FileName = fileName;

            Debugs = debugs;
        }

        public static DebuggerTestCase GetTestCase1()
        {
            return new DebuggerTestCase(
                Deploy.FILE_8_BYTES,
                new IDebug[]
                {
                    new TestDebug
                    {
                        Id = 0x244,
                        Address = 0x0,
                        Bytes = new byte[] { 0x55 },
                        Instruction = "push ebp",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }
                    },
                    new TestDebug
                    {
                        Id = 0x87,
                        Address = 0x1,
                        Bytes = new byte[] { 0x48 },
                        Instruction = "dec eax",
                        Registers = new uint[] { 0xffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2 }
                    },
                    new TestDebug
                    {
                        Id = 0x1ba,
                        Address = 0x2,
                        Bytes = new byte[] { 0x8B, 0x05, 0xB8, 0x13, 0x00, 0x00 },
                        Instruction = "mov eax, dword ptr [0x13b8]", // TODO: Replace bad instruction!
                        Registers = new uint[] { 0xffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8 }
                    }
                });
        }
        public static DebuggerTestCase GetTestCase2()
        {
            return new DebuggerTestCase(
                Deploy.FILE_TEST_EXE,
                new IDebug[]
                {
                    new TestDebug
                    {
                        Id = 0x10a,
                        Address = 0x401000,
                        Bytes = new byte[] { 0xeb, 0x10 },
                        Instruction = "jmp 0x401012",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x401012 }
                    },
                    new TestDebug
                    {
                        Id = 0x1ba,
                        Address = 0x401012,
                        Bytes = new byte[] { 0xa1, 0xbf, 0x61, 0x41, 0x00 },
                        Instruction = "mov eax, dword ptr [0x4161bf]",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x401017 }
                    }
                });
        }

        private struct TestDebug : IDebug
        {
            public uint Id { get; set; }
            public uint Address { get; set; }
            public byte[] Bytes { get; set; }
            public string Instruction { get; set; }
            public uint[] Registers { get; set; }
        }
    }
}
