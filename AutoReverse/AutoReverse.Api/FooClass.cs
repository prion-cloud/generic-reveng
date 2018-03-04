using System.Runtime.InteropServices;

namespace AutoReverse.Api
{
    public class FooClass
    {
        [DllImport("AutoReverse.LibWrapper.dll")]
        private static extern void foo();

        public static void Foo()
        {
            foo();
        }
    }
}
