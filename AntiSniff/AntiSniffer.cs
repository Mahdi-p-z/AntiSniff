using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AntiSniff
{
    public static class AntiSniffer
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
        "network",
        "soap monitor",
        "soapmonitor",
        "fiddler",
        "burpsuit",
        "burp suit",
        "nmap",
        "analyzer",
        "analizer",
        "dump",
        "http"
        };

        private static void CheckProcesses()
        {
            Process[] TaskList = Process.GetProcesses();
            foreach (Process Run in TaskList)
            {
                foreach (string Name in BlackList)
                {
                    if (Run.ProcessName.ToLower().Contains(Name))
                    {
                        Kill();
                    }
                }
            }
        }

        private static void SendRequest()
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://google.com");
                req.ContinueTimeout = 10000;
                req.ReadWriteTimeout = 10000;
                req.Timeout = 10000;
                req.KeepAlive = true;
                req.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36";
                req.Accept = "*/*";
                req.Method = "GET";
                req.Headers.Add("Accept-Language", "en-US,en;q=0.9,fa;q=0.8");
                req.Headers.Add("Accept-Encoding", "gzip, deflate");
                req.AutomaticDecompression = DecompressionMethods.GZip;
                req.ServerCertificateValidationCallback = ValidationCallback;
                req.ServicePoint.Expect100Continue = false;
                using (HttpWebResponse response = req.GetResponse() as HttpWebResponse)
                {
                    if (response.StatusCode != System.Net.HttpStatusCode.OK)
                    {
                        Kill();
                    }
                }
            }
            catch
            {
                Kill();
            }
        }

        private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool flag = sslPolicyErrors > SslPolicyErrors.None;
            bool result;
            if (flag)
            {
                result = false;
            }
            else
            {
                bool flag2 = chain.ChainPolicy.VerificationFlags == X509VerificationFlags.NoFlag && chain.ChainPolicy.RevocationMode == X509RevocationMode.Online;
                if (flag2)
                {
                    result = true;
                }
                else
                {
                    X509Chain x509Chain = new X509Chain();
                    X509ChainElementCollection chainElements = chain.ChainElements;
                    for (int i = 1; i < chainElements.Count - 1; i++)
                    {
                        x509Chain.ChainPolicy.ExtraStore.Add(chainElements[i].Certificate);
                    }
                    result = x509Chain.Build(chainElements[0].Certificate);
                }
            }
            return result;
        }

        private static void CheckRequest()
        {
            try
            {
                SendRequest();
                ServicePointManager.CheckCertificateRevocationList = true;
                HttpWebRequest httpWebRequest = WebRequest.Create("https://google.com") as HttpWebRequest;
                httpWebRequest.Timeout = 10000;
                httpWebRequest.ContinueTimeout = 10000;
                httpWebRequest.ReadWriteTimeout = 10000;
                httpWebRequest.KeepAlive = true;
                httpWebRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0";
                httpWebRequest.Host = "www.google.com";
                httpWebRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                httpWebRequest.Method = "GET";
                httpWebRequest.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidationCallback);
                using (HttpWebResponse httpWebResponse = httpWebRequest.GetResponse() as HttpWebResponse)
                {
                    if (httpWebResponse.StatusCode != HttpStatusCode.OK)
                    {
                        Kill();
                    }
                }
            }
            catch
            {
                Kill();
            }
        }

        private static void Kill()
        {
            Process.GetCurrentProcess().Kill();
        }

        public static void Start(bool checkprocesslist, bool checkdata)
        {
            if (checkprocesslist)
                CheckProcesses();

            if (checkdata)
                CheckRequest();
        }
    }
}
