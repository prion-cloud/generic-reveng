using System;

using Superbr4in.SharpReverse.Api.Factory;

namespace Superbr4in.SharpReverse.Api.Test
{
    public abstract class DebuggerTestCase
    {
        #region Properties

        public bool Amd64 { get; }

        public (IInstructionInfo, IRegisterInfo[])[] DebugResults { get; }

        #endregion

        protected DebuggerTestCase(bool amd64, (IInstructionInfo, IRegisterInfo[])[] debugResults)
        {
            Amd64 = amd64;

            DebugResults = debugResults;
        }

        public static DebuggerTestCase<byte[]> GetTestCase32_Bytes1()
        {
            // http://www.unicorn-engine.org/docs/tutorial.html
            
            return new DebuggerTestCase<byte[]>(
                t => DebuggerFactory.CreateNew(t, false),
                new byte[] { 0x41, 0x4a },
                false,
                new (IInstructionInfo, IRegisterInfo[])[]
                {
                    (
                        new TestInstructionInfo(0xd8, "00000000", new byte[] { 0x41 }, "inc ecx", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000001"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00000001")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x87, "00000001", new byte[] { 0x4a }, "dec edx", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000001"),
                            new TestRegisterInfo("edx", "ffffffff"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00000002")
                        }
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase32_File1()
        {
            return new DebuggerTestCase<string>(
                DebuggerFactory.CreateNew,
                TestDeploy.FILE_TEST_EXE,
                false,
                new (IInstructionInfo, IRegisterInfo[])[]
                {
                    (
                        new TestInstructionInfo(0x10a, "00401000", new byte[] { 0xeb, 0x10 }, "jmp 0x401012", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00401012")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x1ba, "00401012", new byte[] { 0xa1, 0xbf, 0x61, 0x41, 0x00 }, "mov eax, dword ptr [0x4161bf]", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00401017")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x283, "00401017", new byte[] { 0xc1, 0xe0, 0x02 }, "shl eax, 2", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "0040101a")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x1ba, "0040101a", new byte[] { 0xa3, 0xc3, 0x61, 0x41, 0x00 }, "mov dword ptr [0x4161c3], eax", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffff"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "0040101f")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x244, "0040101f", new byte[] { 0x52 }, "push edx", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffffb"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00401020")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x244, "00401020", new byte[] { 0x6a, 0x00 }, "push 0", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff7"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "00401022")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x38, "00401022", new byte[] { 0xe8, 0x65, 0x41, 0x01, 0x00 }, "call 0x41518c", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff3"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "0041518c")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x10a, "0041518c", new byte[] { 0xff, 0x25, 0x3c, 0x12, 0x42, 0x00 }, "jmp dword ptr [0x42123c]", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff3"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", TestEngine.PH)
                        }
                    ),
                    (
                        new TestInstructionInfo(0x1ba, TestEngine.PH, new byte[] { 0x8b, 0xff }, "mov edi, edi", "KERNEL32.GetModuleHandleA"),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff3"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", TestEngine.PH)
                        }
                    ),
                    (
                        new TestInstructionInfo(0x244, TestEngine.PH, new byte[] { 0x55 }, "push ebp", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffef"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", TestEngine.PH)
                        }
                    ),
                    (
                        new TestInstructionInfo(0x1ba, TestEngine.PH, new byte[] { 0x8b, 0xec }, "mov ebp, esp", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "ffffffef"),
                            new TestRegisterInfo("ebp", "ffffffef"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", TestEngine.PH)
                        }
                    ),
                    (
                        new TestInstructionInfo(0x22e, TestEngine.PH, new byte[] { 0x5d }, "pop ebp", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff3"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", TestEngine.PH)
                        }
                    )/*,
                    (
                        new TestInstructionInfo(0x10a, TestEngine.PH, new byte[] { 0xff, 0x25, 0xa0, 0x10, 0x5b, 0x77 }, "jmp dword ptr [0x775b10a0]"),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("eax", "00000000"),
                            new TestRegisterInfo("ebx", "00000000"),
                            new TestRegisterInfo("ecx", "00000000"),
                            new TestRegisterInfo("edx", "00000000"),
                            new TestRegisterInfo("esp", "fffffff3"),
                            new TestRegisterInfo("ebp", "ffffffff"),
                            new TestRegisterInfo("esi", "00000000"),
                            new TestRegisterInfo("edi", "00000000"),
                            new TestRegisterInfo("eip", "0009323e")
                        }
                    )
                    */
                });
        }

        public static DebuggerTestCase<byte[]> GetTestCase64_Bytes1()
        {
            // http://www.capstone-engine.org/lang_c.html

            return new DebuggerTestCase<byte[]>(
                t => DebuggerFactory.CreateNew(t, true),
                new byte[] { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 },
                true,
                new (IInstructionInfo, IRegisterInfo[])[]
                {
                    (
                        new TestInstructionInfo(0x244, "0000000000000000", new byte[] { 0x55 }, "push rbp", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("rax", "0000000000000000"),
                            new TestRegisterInfo("rbx", "0000000000000000"),
                            new TestRegisterInfo("rcx", "0000000000000000"),
                            new TestRegisterInfo("rdx", "0000000000000000"),
                            new TestRegisterInfo("rsp", "00000000fffffff7"),
                            new TestRegisterInfo("rbp", "00000000ffffffff"),
                            new TestRegisterInfo("rsi", "0000000000000000"),
                            new TestRegisterInfo("rdi", "0000000000000000"),
                            new TestRegisterInfo("rip", "0000000000000001")
                        }
                    ),
                    (
                        new TestInstructionInfo(0x1ba, "0000000000000001", new byte[] { 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 }, "mov rax, qword ptr [rip + 0x13b8]", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("rax", "0000000000000000"),
                            new TestRegisterInfo("rbx", "0000000000000000"),
                            new TestRegisterInfo("rcx", "0000000000000000"),
                            new TestRegisterInfo("rdx", "0000000000000000"),
                            new TestRegisterInfo("rsp", "00000000fffffff7"),
                            new TestRegisterInfo("rbp", "00000000ffffffff"),
                            new TestRegisterInfo("rsi", "0000000000000000"),
                            new TestRegisterInfo("rdi", "0000000000000000"),
                            new TestRegisterInfo("rip", "0000000000000008")
                        }
                    )
                });
        }
        public static DebuggerTestCase<string> GetTestCase64_File1()
        {
            return new DebuggerTestCase<string>(
                DebuggerFactory.CreateNew,
                TestDeploy.FILE_HELLOWORLD64_EXE,
                true,
                new (IInstructionInfo, IRegisterInfo[])[]
                {
                    (
                        new TestInstructionInfo(0x146, "0000000000401500", new byte[] { 0x48, 0x83, 0xec, 0x28 }, "sub rsp, 0x28", string.Empty),
                        new IRegisterInfo[]
                        {
                            new TestRegisterInfo("rax", "0000000000000000"),
                            new TestRegisterInfo("rbx", "0000000000000000"),
                            new TestRegisterInfo("rcx", "0000000000000000"),
                            new TestRegisterInfo("rdx", "0000000000000000"),
                            new TestRegisterInfo("rsp", "00000000ffffffd7"),
                            new TestRegisterInfo("rbp", "00000000ffffffff"),
                            new TestRegisterInfo("rsi", "0000000000000000"),
                            new TestRegisterInfo("rdi", "0000000000000000"),
                            new TestRegisterInfo("rip", "0000000000401504")
                        }
                    )
                });
        }

        private struct TestInstructionInfo : IInstructionInfo
        {
            #region Properties
            
            public uint Id { get; }
            public string Address { get; }
            public byte[] Bytes { get; }
            public string Instruction { get; }
            public string Comment { get; }

            #endregion

            public TestInstructionInfo(uint id, string address, byte[] bytes, string instruction, string comment)
            {
                Id = id;
                Address = address;
                Bytes = bytes;
                Instruction = instruction;
                Comment = comment;
            }
        }
        private struct TestRegisterInfo : IRegisterInfo
        {
            #region Properties
            
            public string Name { get; }
            public string Value { get; }

            #endregion

            public TestRegisterInfo(string name, string value)
            {
                Name = name;
                Value = value;
            }
        }
    }

    public class DebuggerTestCase<T> : DebuggerTestCase
    {
        #region Properties

        public Func<T, IDebugger> DebuggerConstructor { get; }

        public T Data { get; }

        #endregion

        public DebuggerTestCase(Func<T, IDebugger> debuggerConstructor, T data, bool amd64,
            (IInstructionInfo, IRegisterInfo[])[] debugResults)
            : base(amd64, debugResults)
        {
            DebuggerConstructor = debuggerConstructor;

            Data = data;
        }
    }
}
