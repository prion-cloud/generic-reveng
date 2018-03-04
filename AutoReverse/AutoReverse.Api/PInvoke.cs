using System;
using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    internal static class PInvoke
    {
        private const string DLL_NAME = "AutoReverse.LibWrapper.dll";

        [DllImport(DLL_NAME)]
        public static extern IntPtr disassembler_open(Architecture architecture, Mode mode, byte[] bytes, int size);

        [DllImport(DLL_NAME)]
        public static extern IntPtr disassembler_close(IntPtr disassembler);

        [DllImport(DLL_NAME)]
        public static extern int disassemble(IntPtr disassembler, out Instruction instruction);
        
        public enum Architecture
        {
            Arm = 0,                // ARM architecture (including Thumb, Thumb-2)
            Arm64,                  // ARM-64, also called AArch64
            Mips,                   // Mips architecture
            X86,                    // X86 architecture (including x86 & x86-64)
            PowerPc,                // PowerPC architecture
            Sparc,                  // Sparc architecture
            SystemZ,                // SystemZ architecture
            XCore,                  // XCore architecture
            Max,
            All = 0xFFFF,           // All architectures - for cs_support()
        }

        [Flags]
        public enum Mode
        {
            LittleEndian = 0,       // little-endian mode (default mode)
            Arm = 0,                // 32-bit ARM
            B16 = 1 << 1,           // 16-bit mode (X86)
            B32 = 1 << 2,           // 32-bit mode (X86)
            B64 = 1 << 3,           // 64-bit mode (X86, PPC)
            Thumb = 1 << 4,         // ARM's Thumb mode, including Thumb-2
            MClass = 1 << 5,        // ARM's Cortex-M series
            V8 = 1 << 6,            // ARMv8 A32 encodings for ARM
            Micro = 1 << 4,         // MicroMips mode (MIPS)
            Mips3 = 1 << 5,         // Mips III ISA
            Mips32R6 = 1 << 6,      // Mips32r6 ISA
            Mipsgp64 = 1 << 7,      // General Purpose Registers are 64-bit wide (MIPS)
            V9 = 1 << 4,            // SparcV9 mode (Sparc)
            BigEndian = 1 << 31,    // big-endian mode
            Mips32 = B32,           // Mips32 ISA (Mips)
            Mips64 = B64,           // Mips64 ISA (Mips)
        }

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
        }
    }
}
