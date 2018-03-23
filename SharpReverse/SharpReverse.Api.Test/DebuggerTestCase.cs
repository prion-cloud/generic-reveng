using System.Collections.Generic;

using SharpReverse.Api.Interface;

namespace SharpReverse.Api.Test
{
    public class DebuggerTestCase
    {
        #region Properties

        public Debugger Debugger { get; }

        public (IInstruction, IRegisterState)[] Debugs { get; }

        #endregion

        private DebuggerTestCase(Debugger debugger, (IInstruction, IRegisterState)[] debugs)
        {
            Debugger = debugger;

            Debugs = debugs;
        }

        public static DebuggerTestCase GetTestCase1()
        {
            return new DebuggerTestCase(
                new Debugger(new byte[] { 0x41, 0x4a }), 
                new (IInstruction, IRegisterState)[]
                {
                    (
                        new TestInstruction
                        {
                            Id = 0xd8,
                            Address = 0x0,
                            Bytes = new byte[] { 0x41 },
                            Instruction = "inc ecx"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x1, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x1 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x87,
                            Address = 0x1,
                            Bytes = new byte[] { 0x4a },
                            Instruction = "dec edx"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x1, 0xffffffff, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x2 }
                        }
                    )
                });
        }
        public static DebuggerTestCase GetTestCase2()
        {
            return new DebuggerTestCase(
                new Debugger(Deploy.FILE_TEST_EXE), 
                new (IInstruction, IRegisterState)[]
                {
                    (
                        new TestInstruction
                        {
                            Id = 0x10a,
                            Address = 0x401000,
                            Bytes = new byte[] { 0xeb, 0x10 },
                            Instruction = "jmp 0x401012"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401012 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x1ba,
                            Address = 0x401012,
                            Bytes = new byte[] { 0xa1, 0xbf, 0x61, 0x41, 0x00 },
                            Instruction = "mov eax, dword ptr [0x4161bf]"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x401017 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x283,
                            Address = 0x401017,
                            Bytes = new byte[] { 0xc1, 0xe0, 0x02 },
                            Instruction = "shl eax, 2"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101a }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x1ba,
                            Address = 0x40101a,
                            Bytes = new byte[] { 0xa3, 0xc3, 0x61, 0x41, 0x00 },
                            Instruction = "mov dword ptr [0x4161c3], eax"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0x0, 0x0, 0x40101f }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x244,
                            Address = 0x40101f,
                            Bytes = new byte[] { 0x52 },
                            Instruction = "push edx"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffffb, 0xffffffff, 0x0, 0x0, 0x401020 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x244,
                            Address = 0x401020,
                            Bytes = new byte[] { 0x6a, 0x00 },
                            Instruction = "push 0"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff7, 0xffffffff, 0x0, 0x0, 0x401022 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x38,
                            Address = 0x401022,
                            Bytes = new byte[] { 0xe8, 0x65, 0x41, 0x01, 0x00 },
                            Instruction = "call 0x41518c"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x41518c }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x10a,
                            Address = 0x41518c,
                            Bytes = new byte[] { 0xff, 0x25, 0x3c, 0x12, 0x42, 0x00 },
                            Instruction = "jmp dword ptr [0x42123c]"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb0 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x1ba,
                            Address = 0x77554fb0,
                            Bytes = new byte[] { 0x8b, 0xff },
                            Instruction = "mov edi, edi"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb2 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x244,
                            Address = 0x77554fb2,
                            Bytes = new byte[] { 0x55 },
                            Instruction = "push ebp"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffff, 0x0, 0x0, 0x77554fb3 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x1ba,
                            Address = 0x77554fb3,
                            Bytes = new byte[] { 0x8b, 0xec },
                            Instruction = "mov ebp, esp"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xffffffef, 0xffffffef, 0x0, 0x0, 0x77554fb5 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x22e,
                            Address = 0x77554fb5,
                            Bytes = new byte[] { 0x5d },
                            Instruction = "pop ebp"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x77554fb6 }
                        }
                    ),
                    (
                        new TestInstruction
                        {
                            Id = 0x10a,
                            Address = 0x77554fb6,
                            Bytes = new byte[] { 0xff, 0x25, 0xa0, 0x10, 0x5b, 0x77 },
                            Instruction = "jmp dword ptr [0x775b10a0]"
                        },
                        new TestRegisterState
                        {
                            Registers = new uint[] { 0x0, 0x0, 0x0, 0x0, 0xfffffff3, 0xffffffff, 0x0, 0x0, 0x0009323e }
                        }
                    )
                });
        }

        private struct TestInstruction : IInstruction
        {
            public uint Id { get; set; }
            public uint Address { get; set; }
            public IEnumerable<byte> Bytes { get; set; }
            public string Instruction { get; set; }
        }
        private struct TestRegisterState : IRegisterState
        {
            public uint[] Registers { get; set; }
        }
    }
}
