using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSniff
{
    public static class AntiSniff
    {
        private static List<string> BlackList = new List<string> {
        "wireshark",
        "wire shark",
        "debugger",
        "debuger",
        "sniff",
        "snif",
        "networkminer",
        "network miner",
        "traffic",
        "trafic",
        "network monitor",
        "networkmonitor",
        "soap monitor",
        "soapmonitor",
        "fiddler",
        "burpsuit",
        "burp suit",
        "nmap"
        };
        private static Process CurrentProcess = Process.GetCurrentProcess();

        private static bool CheckProcesses()
        {
            Process[] TaskList = Process.GetProcesses();
            foreach (Process Run in TaskList)
            {
                foreach (string Name in BlackList)
                {
                    if (Run.ProcessName.ToLower().Contains(Name))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static void Start()
        {
            bool ExitorGo = CheckProcesses();
            if (!ExitorGo)
            {
                AutoClosingMessageBox.Show("Close Sniffer and Run Again!", "Suspicious Program Detected", 3000);
                CurrentProcess.Kill();
            }
        }
    }
}
