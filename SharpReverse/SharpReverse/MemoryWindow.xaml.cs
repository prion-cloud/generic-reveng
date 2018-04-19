using System.Collections.Generic;

using Superbr4in.SharpReverse.Api;

namespace Superbr4in.SharpReverse
{
    public partial class MemoryWindow
    {
        public MemoryWindow(IEnumerable<IMemoryInfo> memoryInfos)
        {
            InitializeComponent();

            foreach (var info in memoryInfos)
                ListView.Items.Add(info);
        }
    }
}
