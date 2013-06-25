/*
    OpenSandbox - build on Eashhook library and C#, 
	it allow you to run windows applications in a sandboxed environment
 
    Copyright (C) 2013 Thomas Jam Pedersen & Igor Polyakov

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Please visit https://github.com/thomas3d/OpenSandbox for more information
    about the project and latest updates.
*/
using System;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Security.AccessControl;

namespace OpenSandbox.Logging
{
    //TODO: if it's save to put failures here into the DebugLogger, do so
    internal class FileAccessLogger : DisposableBase
    {
        private string logFilePath_;
        private AsyncLogger fflCreate;
        private FileAccessLogSender fileLogSender_;
        private DateTime stateStartTime_ = DateTime.Now;
        private enum State {Started, Embedded};
        private State state_ = State.Started;

        public FileAccessLogger(uint redmineID)
        {
            logFilePath_ = Path.GetFullPath(Path.GetTempFileName());
            fflCreate = new AsyncLogger(new FileLogger(logFilePath_));
            fileLogSender_ = new FileAccessLogSender(logFilePath_);
            WriteLine("RedmineID={0}", redmineID);
        }

        private void WriteLine(string format, params object[] args)
        {
            try
            {
                fflCreate.WriteItem(format, args);
            }
            catch { }
        }

        public void NowEmbedded()
        {
            state_ = State.Embedded;
            stateStartTime_ = DateTime.Now;
        }

        internal void FileAccessed(string fullPath)
        {
            int msSinceStart = Convert.ToInt32(DateTime.Now.Subtract(stateStartTime_).TotalMilliseconds);
            string prefix = state_ == State.Embedded ? "" : "-";
            WriteLine("{0}{1}|{2}", prefix,  msSinceStart, fullPath);
        }

        protected override void DisposeManaged()
        {
            fflCreate.Dispose();
            // Sender is disposed after logger because during dispose it
            // sends "shutdown" message to updater which needs fileaccess log to be flushed and closed
            fileLogSender_.Dispose();
        }
    }

    internal class FileAccessLogSender : ThreadBase
    {
        private int EVENT_STOP = 0;
        private WaitHandle[] waitHandles_ = new WaitHandle[] { new AutoResetEvent(false) };
        private string filename_;

        public FileAccessLogSender(string filename)
        {
            filename_ = filename;
            StartThread();
        }

        protected override void ThreadProc()
        {
            // Always sending the first ping so that updater adds this access log
            // and keeps track of it
            //SendPipeMessageToService(isShutdown: false);
            int PING_INTERVAL = 60 * 1000; // Interval to remind updater that title is still alive so
                                           // that it does not send the access log yet not full
            // TODO: make sure updater deletes the temporary file of access log after sending to avoid
            // disk space collapse
            while (true)
            {
                int waitResult = WaitHandle.WaitAny(waitHandles_, PING_INTERVAL);
                bool stopping = waitResult == EVENT_STOP;
                // SendPipeMessageToService(isShutdown: stopping);
                if (stopping)
                    break;
            }
        }

        protected override void DisposeUnmanaged()
        {
            ((AutoResetEvent)waitHandles_[EVENT_STOP]).Set();
            thread_.Join();
        }
    }
}
