using System.Collections.Generic;

namespace SharpReverse.Api.Test
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
                Deploy.FILE_TEST_1,
                new IDebug[]
                {
                    new TestDebug
                    {
                        Id = 0xd8,
                        Address = 0x0,
                        Bytes = new byte[] { 0x41 },
                        Instruction = "inc ecx",
                        Registers = new uint[] { 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 }
                    },
                    new TestDebug
                    {
                        Id = 0x87,
                        Address = 0x1,
                        Bytes = new byte[] { 0x4a },
                        Instruction = "dec edx",
                        Registers = new uint[] { 0x0, 0x0, 0x1, 0xffffffff, 0x0, 0x0, 0x0, 0x0, 0x2 }
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
                    },
                    new TestDebug
                    {
                        Id = 0x283,
                        Address = 0x401017,
                        Bytes = new byte[] { 0xc1, 0xe0, 0x02 },
                        Instruction = "shl eax, 2",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40101a }
                    },
                    new TestDebug
                    {
                        Id = 0x1ba,
                        Address = 0x40101a,
                        Bytes = new byte[] { 0xa3, 0xc3, 0x61, 0x41, 0x00 },
                        Instruction = "mov dword ptr [0x4161c3], eax",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40101f }
                    },
                    new TestDebug
                    {
                        Id = 0x244,
                        Address = 0x40101f,
                        Bytes = new byte[] { 0x52 },
                        Instruction = "push edx",
                        Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x401020 }
                    }
                });
        }

        private struct TestDebug : IDebug
        {
            public uint Id { get; set; }
            public uint Address { get; set; }
            public IEnumerable<byte> Bytes { get; set; }
            public string Instruction { get; set; }
            public uint[] Registers { get; set; }
        }
    }
}
