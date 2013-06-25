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
using System.Runtime.Serialization;

namespace OpenSandbox
{
    [Serializable]
    internal class Win32Exception : ApplicationException
    {
        internal int ErrorCode { get; set; }

        // All ctors made protected so that user may use
        // only CheckResult method for throwing appropriate class
        protected Win32Exception() { }
        protected Win32Exception(int errorCode)
            : base(string.Format("Registry error {0}", errorCode))
        {
            ErrorCode = errorCode;
        }
        protected Win32Exception(string message) : base(message) { }
        protected Win32Exception(string message, System.Exception inner)
            : base(message, inner)
        { }
        protected Win32Exception(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ErrorCode = (int)info.GetValue("ErrorCode", typeof(int));
        }

        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ErrorCode", ErrorCode);
        }

        internal static bool CheckIfFoundAndNoError(int result)
        {
            if (result == 0) return true;
            if (result == (int)Win32Api.Error.ERROR_FILE_NOT_FOUND) return false;
            throw Create(result);
        }

        internal static void CheckResult(int result)
        {
            if (result == 0) return;
            throw Create(result);
        }

        internal static Win32Exception Create(int result)
        {
            switch (result)
            {
                case (int)Win32Api.Error.ERROR_FILE_NOT_FOUND:
                    return new FileNotFoundException();
                case (int)Win32Api.Error.ERROR_ACCESS_DENIED:
                    return new AccessDeniedException();
                case (int)Win32Api.Error.ERROR_INVALID_HANDLE:
                    return new InvalidHandleException();
                default:
                    return new Win32Exception(result);
            }
        }

        internal delegate void Operation();
        internal static int CatchError(Operation operation)
        {
            try
            {
                operation();
                return 0;
            }
            catch (Win32Exception ex)
            {
                return ex.ErrorCode;
            }
        }

        internal delegate bool TryOperation();
        internal static int CatchError(TryOperation operation)
        {
            try
            {
                if (!operation())
                    return (int)Win32Api.Error.ERROR_FILE_NOT_FOUND;
                return 0;
            }
            catch (Win32Exception ex)
            {
                return ex.ErrorCode;
            }
        }
    }

    [Serializable]
    internal class FileNotFoundException : Win32Exception
    {
        internal FileNotFoundException()
            : base((int)Win32Api.Error.ERROR_FILE_NOT_FOUND)
        { }
        protected FileNotFoundException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        { }
    }

    [Serializable]
    internal class AccessDeniedException : Win32Exception
    {
        internal AccessDeniedException()
            : base((int)Win32Api.Error.ERROR_ACCESS_DENIED)
        { }
        protected AccessDeniedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        { }
    }

    [Serializable]
    internal class InvalidHandleException : Win32Exception
    {
        internal InvalidHandleException()
            : base((int)Win32Api.Error.ERROR_INVALID_HANDLE)
        { }
        protected InvalidHandleException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        { }
    }

}
