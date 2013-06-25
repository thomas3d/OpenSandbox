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
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenSandbox.Crypto
{
    internal class AESProvider : ICryptoProvider
    {
        private ICryptoTransform decryptor_;
        private ICryptoTransform encryptor_;

        internal AESProvider(string keyString)
        {
            // Todo: find your own way to convert keyString into byte arrays. 
            byte[] key = new byte[32];
            byte[] IV = new byte[16];
            using (Aes aesAlg = Aes.Create())
            {
                decryptor_ = aesAlg.CreateDecryptor(key, IV);
                encryptor_ = aesAlg.CreateEncryptor(key, IV);
            }
        }

        public IReader CreateReader(IReader encrypted)
        {
            CryptoStream stream = new CryptoStream(new ReaderStream(encrypted), decryptor_, CryptoStreamMode.Read);
            return new StreamReader(stream);
        }

        public IWriter CreateWriter(IWriter encrypted)
        {
            CryptoStream stream = new CryptoStream(new WriterStream(encrypted), encryptor_, CryptoStreamMode.Write);
            return new StreamWriter(stream);
        }
    }

    internal class NotImplementedStream : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override long Length
        {
            get { throw new NotImplementedException(); }
        }

        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }
    }

    internal class ReaderStream : NotImplementedStream
    {
        IReader reader_;

        internal ReaderStream(IReader reader)
        {
            reader_ = reader;
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (offset != 0) throw new NotImplementedException();
            using (HGlobalPtr pBuffer= new HGlobalPtr(count))
            {
                int cbRead = reader_.Read(pBuffer.Ptr, count);
                Marshal.Copy(pBuffer.Ptr, buffer, 0, cbRead);
                return cbRead;
            }
        }
    }

    internal class WriterStream : NotImplementedStream
    {
        IWriter writer_;

        internal WriterStream(IWriter writer)
        {
            writer_ = writer;
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (offset != 0) throw new NotImplementedException();
            using (HGlobalPtr pBuffer = new HGlobalPtr(count))
            {
                Marshal.Copy(buffer, 0, pBuffer.Ptr, count);
                int cbWritten = writer_.Write(pBuffer.Ptr, count);
                if (cbWritten < count)
                    throw new IOException("IWrite interface written less bytes than expected");
            }
        }
    }

    internal class StreamReader : IReader
    {
        private Stream stream_;

        internal StreamReader(Stream stream)
        {
            stream_ = stream;
        }

        public int Read(IntPtr pData, int cbData)
        {
            byte[] buffer = new byte[cbData];
            int cbRead = stream_.Read(buffer, 0, cbData);
            Marshal.Copy(buffer, 0, pData, cbRead);
            return cbRead;
        }
    }

    internal class StreamWriter : IWriter
    {
        private Stream stream_;

        internal StreamWriter(Stream stream)
        {
            stream_ = stream;
        }

        public int Write(IntPtr pData, int cbData)
        {
            byte[] buffer = new byte[cbData];
            Marshal.Copy(pData, buffer, 0, cbData);
            stream_.Write(buffer, 0, cbData);
            return cbData;
        }
    }
}
