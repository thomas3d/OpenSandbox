using System;
using System.Diagnostics;
using OpenSandbox;
using OpenSandbox.Crypto;
using EasyHook;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels.Ipc;
using System.IO;
using System.Windows.Forms;
using System.Xml;

namespace DemoApp
{
    public class EasyHookWrapper
    {
        private IpcServerChannel demoServer_;
        private String channelName_ = null;

        public static void Start(string exeFilename, string reghiveFile)
        {
            // use native win32 methods startup a process in suspended mode
            // inject hooking lib
            int processId = 0;
            string paramsXml = "<xml>reghiveFile</xml>";
            EasyHookWrapper ehw = new EasyHookWrapper();
            ehw.Inject(processId, paramsXml);
            // after injection of hooks the process will start automatically. 
        }

        private void Inject(Int32 processId, string paramsXml)
        {
            demoServer_ = RemoteHooking.IpcCreateServer<IPCInterface>(ref channelName_, WellKnownObjectMode.Singleton);
            string RoozzSandboxPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "OpenSandbox.dll");

            IPCInterface.PerformanceHandler = ReportPerformance;

            RemoteHooking.Inject(
                    processId,
                    RoozzSandboxPath, // 32-bit version (the same because AnyCPU)
                    RoozzSandboxPath, // 64-bit version (the same because AnyCPU)
                    // the optional parameter list...
                    channelName_, paramsXml);
            IPCInterface.WaitForInjection(processId);
        }

        public void ReportPerformance(TimeSpan startupTime, int regCalls, uint redmineId)
        {
            Debug.Print(startupTime.ToString() + ", " + regCalls.ToString());
        }
    }

    public class CryptoHooksHolder : IDisposable, IHookHolderAndCallback
    {
        private InstalledHooks installedHooks_;

        public CryptoHooksHolder()
        {
        }

        public void Init(string xml)
        {
            installedHooks_ = new InstalledHooks(this, CryptoFunctionsHookLib.Hooks);
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);
                foreach (XmlNode node in doc.DocumentElement.GetElementsByTagName("file"))
                {
                    FileEncryptionLayer.AttachFile(node.Attributes["name"].Value, node.Attributes["pwd"].Value);
                }
            }
            catch { }
        }

        public Hook LookUp(LocalHook handle)
        {
            return installedHooks_.LookUp(handle);
        }

        public void Dispose()
        {
            installedHooks_.Dispose();
        }
    }
}
