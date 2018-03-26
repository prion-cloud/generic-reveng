using System;

namespace SharpReverse.Api.Test
{
    public abstract class DebuggerTestCase
    {
        #region Properties

        public bool Mode64 { get; }

        public (IInstructionInfo, IRegisterInfo)[] DebugInfos { get; }

        #endregion

        protected DebuggerTestCase(
            bool mode64,
            (IInstructionInfo, IRegisterInfo)[] debugInfos)
        {
            Mode64 = mode64;

            DebugInfos = debugInfos;
        }

        public static DebuggerTestCase<byte[]> GetTestCase32_Bytes1()
        {
            // http://www.unicorn-engine.org/docs/tutorial.html
            
            return new DebuggerTestCase<byte[]>(
                t => new Debugger(t),
                new byte[] { 0x41, 0x4a },
                false,
                new (IInstructionInfo, IRegisterInfo)[]
                {
                    (
                        new TestInstructionInfo
                        {
                            Id = 0xd8,
                            Address = 0x0,
                            Bytes = new byte[] { 0x41 },
                            Instruction = "inc ecx"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x1, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x1 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x87,
                            Address = 0x1,
                            Bytes = new byte[] { 0x4a },
                            Instruction = "dec edx"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x1, 0xffffffff, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x2 }
                        }
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase32_File1()
        {
            return new DebuggerTestCase<string>(
                t => new Debugger(t),
                TestDeploy.FILE_TEST_EXE,
                false,
                new (IInstructionInfo, IRegisterInfo)[]
                {
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x10a,
                            Address = 0x401000,
                            Bytes = new byte[] { 0xeb, 0x10 },
                            Instruction = "jmp 0x401012"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401012 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x1ba,
                            Address = 0x401012,
                            Bytes = new byte[] { 0xa1, 0xbf, 0x61, 0x41, 0x00 },
                            Instruction = "mov eax, dword ptr [0x4161bf]"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401017 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x283,
                            Address = 0x401017,
                            Bytes = new byte[] { 0xc1, 0xe0, 0x02 },
                            Instruction = "shl eax, 2"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101a }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x1ba,
                            Address = 0x40101a,
                            Bytes = new byte[] { 0xa3, 0xc3, 0x61, 0x41, 0x00 },
                            Instruction = "mov dword ptr [0x4161c3], eax"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101f }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x244,
                            Address = 0x40101f,
                            Bytes = new byte[] { 0x52 },
                            Instruction = "push edx"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffb, 0xffffffff, 0x0, 0x0, 0x401020 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x244,
                            Address = 0x401020,
                            Bytes = new byte[] { 0x6a, 0x00 },
                            Instruction = "push 0"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff7, 0xffffffff, 0x0, 0x0, 0x401022 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x38,
                            Address = 0x401022,
                            Bytes = new byte[] { 0xe8, 0x65, 0x41, 0x01, 0x00 },
                            Instruction = "call 0x41518c"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x41518c }
                        }
                    ),
                    /*
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x10a,
                            Address = 0x41518c,
                            Bytes = new byte[] { 0xff, 0x25, 0x3c, 0x12, 0x42, 0x00 },
                            Instruction = "jmp dword ptr [0x42123c]"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb0 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x1ba,
                            Address = 0x77554fb0,
                            Bytes = new byte[] { 0x8b, 0xff },
                            Instruction = "mov edi, edi"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb2 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x244,
                            Address = 0x77554fb2,
                            Bytes = new byte[] { 0x55 },
                            Instruction = "push ebp"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffff, 0x0, 0x0, 0x77554fb3 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x1ba,
                            Address = 0x77554fb3,
                            Bytes = new byte[] { 0x8b, 0xec },
                            Instruction = "mov ebp, esp"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffef, 0x0, 0x0, 0x77554fb5 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x22e,
                            Address = 0x77554fb5,
                            Bytes = new byte[] { 0x5d },
                            Instruction = "pop ebp"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb6 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x10a,
                            Address = 0x77554fb6,
                            Bytes = new byte[] { 0xff, 0x25, 0xa0, 0x10, 0x5b, 0x77 },
                            Instruction = "jmp dword ptr [0x775b10a0]"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x0009323e }
                        }
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
                new (IInstructionInfo, IRegisterInfo)[]
                {
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x244,
                            Address = 0x0,
                            Bytes = new byte[] { 0x55 },
                            Instruction = "push rbp"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffffffffff7, 0xffffffffffffffff, 0x0, 0x0, 0x1 }
                        }
                    ),
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x1ba,
                            Address = 0x1,
                            Bytes = new byte[] { 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 },
                            Instruction = "mov rax, qword ptr [rip + 0x13b8]"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffffffffff7, 0xffffffffffffffff, 0x0, 0x0, 0x8 }
                        }
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase64_File1()
        {
            return new DebuggerTestCase<string>(
                t => new Debugger(t),
                TestDeploy.FILE_HELLOWORLD64_EXE,
                true,
                new (IInstructionInfo, IRegisterInfo)[]
                {
                    (
                        new TestInstructionInfo
                        {
                            Id = 0x146,
                            Address = 0x401500,
                            Bytes = new byte[] { 0x48, 0x83, 0xec, 0x28 },
                            Instruction = "sub rsp, 0x28"
                        },
                        new TestRegisterInfo
                        {
                            Registers = new ulong[] { 0x0, 0x0, 0x0, 0x0, 0xffffffffffffffd7, 0xffffffffffffffff, 0x0, 0x0, 0x401504 }
                        }
                    )
                });
        }

        private struct TestInstructionInfo : IInstructionInfo
        {
            public uint Id { get; set; }
            public ulong Address { get; set; }
            public byte[] Bytes { get; set; }
            public string Instruction { get; set; }
        }
        private struct TestRegisterInfo : IRegisterInfo
        {
            public ulong[] Registers { get; set; }
        }
    }

    public class DebuggerTestCase<T> : DebuggerTestCase
    {
        #region Properties

        public Func<T, Debugger> DebuggerConstructor { get; }

        public T Data { get; }

        #endregion

        public DebuggerTestCase(
            Func<T, Debugger> debuggerConstructor,
            T data,
            bool mode64,
            (IInstructionInfo, IRegisterInfo)[] debugInfos)
            : base(mode64, debugInfos)
        {
            DebuggerConstructor = debuggerConstructor;

            Data = data;
        }
    }
}
