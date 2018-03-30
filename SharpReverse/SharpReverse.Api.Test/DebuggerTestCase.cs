using System;
using System.Linq;

namespace SharpReverse.Api.Test
{
    public abstract class DebuggerTestCase
    {
        #region Properties

        public bool Amd64 { get; }

        public (TestInstructionInfo, TestRegisterInfo)[] DebugResults { get; }

        #endregion

        protected DebuggerTestCase(bool amd64, (TestInstructionInfo, TestRegisterInfo)[] debugResults)
        {
            Amd64 = amd64;

            DebugResults = debugResults;
        }

        public static DebuggerTestCase<byte[]> GetTestCase32_Bytes1()
        {
            // http://www.unicorn-engine.org/docs/tutorial.html
            
            return new DebuggerTestCase<byte[]>(
                t => new Debugger(t),
                new byte[] { 0x41, 0x4a },
                false,
                new[]
                {
                    (
                        new TestInstructionInfo(0xd8, 0x0, new byte[] { 0x41 }, "inc ecx"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x1, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x1 })
                    ),
                    (
                        new TestInstructionInfo(0x87, 0x1, new byte[] { 0x4a }, "dec edx"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x1, 0xffffffff, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x2 })
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase32_File1()
        {
            return new DebuggerTestCase<string>(
                t => new Debugger(t),
                TestDeploy.FILE_TEST_EXE,
                false,
                new[]
                {
                    (
                        new TestInstructionInfo(0x10a, 0x401000, new byte[] { 0xeb, 0x10 }, "jmp 0x401012"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401012 })
                    ),
                    (
                        new TestInstructionInfo(0x1ba, 0x401012, new byte[] { 0xa1, 0xbf, 0x61, 0x41, 0x00 }, "mov eax, dword ptr [0x4161bf]"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401017 })
                    ),
                    (
                        new TestInstructionInfo(0x283, 0x401017, new byte[] { 0xc1, 0xe0, 0x02 }, "shl eax, 2"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101a })
                    ),
                    (
                        new TestInstructionInfo(0x1ba, 0x40101a, new byte[] { 0xa3, 0xc3, 0x61, 0x41, 0x00 }, "mov dword ptr [0x4161c3], eax"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101f })
                    ),
                    (
                        new TestInstructionInfo(0x244, 0x40101f, new byte[] { 0x52 }, "push edx"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffb, 0xffffffff, 0x0, 0x0, 0x401020 })
                    ),
                    (
                        new TestInstructionInfo(0x244, 0x401020, new byte[] { 0x6a, 0x00 }, "push 0"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff7, 0xffffffff, 0x0, 0x0, 0x401022 })
                    ),
                    (
                        new TestInstructionInfo(0x38, 0x401022, new byte[] { 0xe8, 0x65, 0x41, 0x01, 0x00 }, "call 0x41518c"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x41518c })
                    ),
                    (
                        new TestInstructionInfo(0x10a, 0x41518c, new byte[] { 0xff, 0x25, 0x3c, 0x12, 0x42, 0x00 }, "jmp dword ptr [0x42123c]"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x4fb0 }, (8, 0xffff) )
                    ),
                    (
                        new TestInstructionInfo(0x1ba, 0x4fb0, new byte[] { 0x8b, 0xff }, "mov edi, edi", 0xffff),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x4fb2 }, (8, 0xffff))
                    ),
                    (
                        new TestInstructionInfo(0x244, 0x4fb2, new byte[] { 0x55 }, "push ebp", 0xffff),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffff, 0x0, 0x0, 0x4fb3 }, (8, 0xffff))
                    ),
                    (
                        new TestInstructionInfo(0x1ba, 0x4fb3, new byte[] { 0x8b, 0xec }, "mov ebp, esp", 0xffff),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffef, 0x0, 0x0, 0x4fb5 }, (8, 0xffff))
                    ),
                    (
                        new TestInstructionInfo(0x22e, 0x4fb5, new byte[] { 0x5d }, "pop ebp", 0xffff),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x4fb6 }, (8, 0xffff))
                    )/*,
                    (
                        new TestInstructionInfo(0x10a, 0x4fb6, new byte[] { 0xff, 0x25, 0xa0, 0x10, 0x5b, 0x77 }, "jmp dword ptr [0x775b10a0]", 0xffff),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x0009323e })
                    )
                    */
                });
        }

        public static DebuggerTestCase<byte[]> GetTestCase64_Bytes1()
        {
            // http://www.capstone-engine.org/lang_c.html

            return new DebuggerTestCase<byte[]>(
                t => new Debugger(t),
                new byte[] { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 },
                true,
                new[]
                {
                    (
                        new TestInstructionInfo(0x244, 0x0, new byte[] { 0x55 }, "push rbp"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffffffffff7, 0xffffffffffffffff, 0x0, 0x0, 0x1 })
                    ),
                    (
                        new TestInstructionInfo(0x1ba, 0x1, new byte[] { 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 }, "mov rax, qword ptr [rip + 0x13b8]"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffffffffff7, 0xffffffffffffffff, 0x0, 0x0, 0x8 })
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase64_File1()
        {
            return new DebuggerTestCase<string>(
                t => new Debugger(t),
                TestDeploy.FILE_HELLOWORLD64_EXE,
                true,
                new[]
                {
                    (
                        new TestInstructionInfo(0x146, 0x401500, new byte[] { 0x48, 0x83, 0xec, 0x28 }, "sub rsp, 0x28"),
                        new TestRegisterInfo(new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffffffffffd7, 0xffffffffffffffff, 0x0, 0x0, 0x401504 })
                    )
                });
        }
    }

    public class DebuggerTestCase<T> : DebuggerTestCase
    {
        #region Properties

        public Func<T, Debugger> DebuggerConstructor { get; }

        public T Data { get; }

        #endregion

        public DebuggerTestCase(Func<T, Debugger> debuggerConstructor, T data, bool amd64,
            (TestInstructionInfo, TestRegisterInfo)[] debugResults)
            : base(amd64, debugResults)
        {
            DebuggerConstructor = debuggerConstructor;

            Data = data;
        }
    }

    public struct TestInstructionInfo
    {
        public readonly uint Id;
        public readonly (ulong, ulong?) Address;
        public readonly byte[] Bytes;
        public readonly string Instruction;

        public TestInstructionInfo(uint id, ulong address, byte[] bytes, string instruction, ulong? addressMask = null)
        {
            Id = id;
            Address = (address, addressMask);
            Bytes = bytes;
            Instruction = instruction;
        }
    }
    public struct TestRegisterInfo
    {
        public readonly (ulong, ulong?)[] Registers;

        public TestRegisterInfo(ulong[] registers, params (int, ulong)[] registerMasks)
        {
            Registers = registers.Select<ulong, (ulong, ulong?)>(r => (r, null)).ToArray();
            foreach (var m in registerMasks)
                Registers[m.Item1].Item2 = m.Item2;
        }
    }
}
