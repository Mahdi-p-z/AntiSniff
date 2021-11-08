using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AntiSniff
{
    class AutoClosingMessageBox
    {
        private AutoClosingMessageBox(string text, string caption, int timeout)
        {
            this._caption = caption;
            this._timeoutTimer = new System.Threading.Timer(new TimerCallback(this.OnTimerElapsed), null, timeout, -1);
            using (this._timeoutTimer)
            {
                MessageBox.Show(text, caption);
            }
        }

        public static void Show(string text, string caption, int timeout)
        {
            new AutoClosingMessageBox(text, caption, timeout);
        }

        private void OnTimerElapsed(object state)
        {
            IntPtr intPtr = AutoClosingMessageBox.FindWindow("#32770", this._caption);
            bool flag = intPtr != IntPtr.Zero;
            if (flag)
            {
                AutoClosingMessageBox.SendMessage(intPtr, 16U, IntPtr.Zero, IntPtr.Zero);
            }
            this._timeoutTimer.Dispose();
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private System.Threading.Timer _timeoutTimer;

        private string _caption;

        private const int WM_CLOSE = 16;
    }
}
