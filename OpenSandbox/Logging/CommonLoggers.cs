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
using EasyHook;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using OpenSandbox.Logging;

namespace OpenSandbox
{
    internal interface ILogger : IDisposable
    {
        // Not thread-safe, does not throw any exceptions
        void WriteItem(KeyValuePair<string, object[]> item);
        void Flush();
    }

    internal class AsyncLogger : ThreadBase
    {
        private static int EVENT_FLUSH_BUFFER = 0;
        private static int EVENT_STOP_LOGGER = 1;
        private WaitHandle[] waitHandles_;

        private Queue<KeyValuePair<string, object[]>> messages_;
        private Queue<KeyValuePair<string, object[]>> processingMessages_;

        private ILogger logger_;

        // Timeout to force buffer flush
        private static int BUFFER_FLUSH_TIMEOUT = 1000; 

        internal AsyncLogger(ILogger logger)
        {
            logger_ = logger;

            messages_ = new Queue<KeyValuePair<string, object[]>>();
            processingMessages_ = new Queue<KeyValuePair<string, object[]>>();

            waitHandles_ = new WaitHandle[] 
            {
                new AutoResetEvent(false),
                new AutoResetEvent(false)
            };

            StartThread();
        }

        internal virtual void WriteItem(string format, params object[] args)
        {
            // Performing formatting immediately because args may become out of date later or die
            args = new object[] { String.Format(format, args) };
            format = "{0}";
            lock (this)
            {
                messages_.Enqueue(new KeyValuePair<string, object[]>(format, args));
            }
        }

        internal void ForceFlush()
        {
            // Notify logging thread
            ((AutoResetEvent)waitHandles_[EVENT_FLUSH_BUFFER]).Set();
        }

        protected override void DisposeUnmanaged()
        {
            ((AutoResetEvent)waitHandles_[EVENT_STOP_LOGGER]).Set();
            thread_.Join();

            logger_.Dispose();
        }

        protected override void ThreadProc()
        {
            while (true)
            {
                // Sleep till event fired or timeout reached
                int waitResult = WaitHandle.WaitAny(waitHandles_, BUFFER_FLUSH_TIMEOUT);

                FlushMessage();

                if (waitResult == EVENT_STOP_LOGGER)
                    break;
            }
        }

        private void FlushMessage()
        {
            // Swap message buffers
            lock (this)
            {
                Queue<KeyValuePair<string, object[]>> tmp = processingMessages_;
                processingMessages_ = messages_;
                messages_ = tmp;
            }

            foreach (KeyValuePair<string, object[]> item in processingMessages_)
            {
                logger_.WriteItem(item);
            }

            logger_.Flush();

            processingMessages_.Clear();
        }
    }

    internal class FileLogger : ILogger
    {
        internal FileLogger(string logFilePath)
        {
            logStream_ = new StreamWriter(logFilePath, true, Encoding.Unicode);
        }

        public void WriteItem(KeyValuePair<string, object[]> item)
        {
            try
            {
                logStream_.WriteLine(item.Key, item.Value);
            }
            // Catching everything except AppDomainUnloadedException which may occur and need not
            // to be suppressed
            catch (AppDomainUnloadedException) { throw; }
            catch { }
        }

        public void Flush()
        {
            try
            {
                logStream_.Flush();
            }
            catch (AppDomainUnloadedException) { throw; }
            catch { }
        }

        public void Dispose()
        {
            try
            {
                logStream_.Close();
                // Both IOException and ObjectDisposedException may happen here,
                // suppressing them
            }
            catch { }
        }

        System.IO.StreamWriter logStream_;
    }
}
