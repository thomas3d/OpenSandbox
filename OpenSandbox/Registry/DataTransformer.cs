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
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    internal enum StringFormat { Ansi, Unicode };

    internal interface IString
    {
        bool EndsWithNullChar();
        void AddNullCharAtEnd();
        int Length { get; }
        void CopyTo(IntPtr dst, StringFormat dstFormat);
    }

    internal class ManagedString : IString
    {
        private string value_;

        internal ManagedString(string value)
        {
            value_ = value;
        }

        public bool EndsWithNullChar() { return value_.EndsWith("\0"); }
        public void AddNullCharAtEnd() { value_ += "\0"; }
        public int Length { get { return value_.Length; } }
        public void CopyTo(IntPtr dst, StringFormat dstFormat)
        {
            using (HGlobalPtr pStr =
                new HGlobalPtr(dstFormat == StringFormat.Ansi ?
                    Marshal.StringToHGlobalAnsi(value_) :
                    Marshal.StringToHGlobalUni(value_)))
            {
                PInvokeHelper.Copy(pStr.Ptr, dst, Length * Data.BytesPerChar(dstFormat));
            }
        }
    }

    internal class BytesString : IString
    {
        IntPtr pSrcData_;
        private byte[] bytes_;
        StringFormat format_;

        internal BytesString(IntPtr pSrcData, int cbSrcData)
        {
            pSrcData_ = pSrcData;
            bytes_ = new byte[cbSrcData];
            if (cbSrcData > 0)
                Marshal.Copy(pSrcData, bytes_, 0, cbSrcData);
            format_ = GuessFormat();
        }

        public bool EndsWithNullChar()
        {
            if (format_ == StringFormat.Ansi)
                return bytes_.Length >= 1 && bytes_[bytes_.Length - 1] == 0;
            return bytes_.Length >= 2 && bytes_[bytes_.Length - 1] == 0
                && bytes_[bytes_.Length - 2] == 0;
        }

        public void AddNullCharAtEnd()
        {
            // Assumming here that default value of byte is 0
            Array.Resize(ref bytes_, bytes_.Length + Data.BytesPerChar(format_));
        }

        public int Length { get { return bytes_.Length / Data.BytesPerChar(format_); } }

        public void CopyTo(IntPtr dst, StringFormat dstFormat)
        {
            // For now only Uni->Ansi conversion is needed
            Debug.Assert(dstFormat == StringFormat.Ansi);
            if (dstFormat != StringFormat.Ansi)
                throw Win32Exception.Create((int)Win32Api.Error.ERROR_INVALID_PARAMETER);
            if (format_ == StringFormat.Unicode)
            {
                PInvokeHelper.StringUniToAnsi(pSrcData_, dst, Length);
            }
            else
            {
                Marshal.Copy(bytes_, 0, dst, bytes_.Length);
            }
        }

        private StringFormat GuessFormat()
        {
            bool nonTrailingZeros = false;
            int nTrailingZeros = 0;
            bool inZeroTrail = true;
            for (int i = bytes_.Length - 1; i >= 0; --i)
            {
                if (inZeroTrail && bytes_[i] != 0)
                {
                    inZeroTrail = false;
                    continue;
                }
                if (inZeroTrail && bytes_[i] == 0)
                {
                    ++nTrailingZeros;
                    continue;
                }
                if (!inZeroTrail && bytes_[i] == 0)
                {
                    nonTrailingZeros = true;
                    continue;
                }
            }
            // This is a heuristic criterion for non-ansi string
            return nonTrailingZeros || (nTrailingZeros != 1 && nTrailingZeros != 3) ?
                StringFormat.Unicode : StringFormat.Ansi;
        }
    }

    internal class Data
    {
        internal enum CountIn { Chars, Bytes };

        [Flags]
        internal enum NullCharHandling
        {
            Default = 0,
            NotAddingIfNotPresent = 1,
            NotCountingOnReturn = 2
        }

        private IntPtr ptr_;
        private IntPtr pCount_;
        private CountIn countType_;

        internal IntPtr Ptr { get { return ptr_; } }
        internal IntPtr PCount { get { return pCount_; } }
        internal CountIn CountType { get { return countType_; } }

        internal Data(IntPtr ptr, IntPtr pCount, CountIn countType)
        {
            ptr_ = ptr;
            pCount_ = pCount;
            countType_ = countType;
        }

        internal static int BytesPerChar(StringFormat format)
        {
            return format == StringFormat.Ansi ? 1 : sizeof(char);
        }

        internal int FillWithString(IString str, StringFormat dstFormat,
            NullCharHandling nullCharHandling)
        {
            if (pCount_ == IntPtr.Zero)
            {
                if (ptr_ != IntPtr.Zero) return (int)Win32Api.Error.ERROR_INVALID_PARAMETER;
                return 0;
            }
            int countFactor = CountType == Data.CountIn.Chars ? BytesPerChar(dstFormat) : 1;
            int bytesAvail = Marshal.ReadInt32(pCount_) * countFactor;

            if (!str.EndsWithNullChar() &&
                (nullCharHandling & NullCharHandling.NotAddingIfNotPresent) == 0)
            {
                str.AddNullCharAtEnd();
            }

            int bytesReq = str.Length * BytesPerChar(dstFormat);

            int bytesReturned = bytesReq;
            if (str.EndsWithNullChar() &&
                (nullCharHandling & NullCharHandling.NotCountingOnReturn) != 0)
            {
                bytesReturned -= BytesPerChar(dstFormat);
            }
            Marshal.WriteInt32(pCount_, bytesReturned / countFactor);

            if (ptr_ == IntPtr.Zero || bytesAvail < bytesReq)
            {
                if (ptr_ == IntPtr.Zero) return 0;
                return (int)Win32Api.Error.ERROR_MORE_DATA;
            }
            str.CopyTo(ptr_, dstFormat);
            return 0;
        }
    }

    internal class DataTransformer
    {
        internal delegate int Operation(IntPtr pdwType, Data dst);
        internal delegate bool Condition(Win32Api.Error result, Win32Api.RegValueType type);
        internal delegate int Transformer(Win32Api.RegValueType type, IntPtr pSrcData,
            int pcbSrcData);

        internal static bool TryAlterData(IntPtr pdwType, Data dst,
            Operation operation, Condition condition, Transformer transformer)
        {
            // We call operation in original way to handle all the cases other
            // than when the altering condition is true
            // But if we call original operation, then we might not know some condition
            // params like data type if user provided null pointers, for instance
            using (HGlobalPtr newpdwType = new HGlobalPtr(Marshal.SizeOf(typeof(uint))),
                newpcbData = new HGlobalPtr(Marshal.SizeOf(typeof(uint))))
            {
//                Marshal.WriteInt32(newpcbData.Ptr, 0);
                Marshal.WriteInt32(newpcbData.Ptr, -1);
                int result = operation(newpdwType.Ptr, new Data(IntPtr.Zero, newpcbData.Ptr, Data.CountIn.Bytes));
                int type = Marshal.ReadInt32(newpdwType.Ptr);
                // if pcbData == IntPtr.Zero => pData too - data is not to be read
                if (dst.PCount == IntPtr.Zero || !condition(unchecked((Win32Api.Error)result),
                    unchecked((Win32Api.RegValueType)type)))
                {
                    return Win32Exception.CheckIfFoundAndNoError(operation(pdwType, dst));
                }
                if (pdwType != IntPtr.Zero)
                {
                    Marshal.WriteInt32(pdwType, type);
                }
                using (HGlobalPtr newpData = new HGlobalPtr(Marshal.ReadInt32(newpcbData.Ptr)))
                {
                    // The full value is retrieved even if pData == IntPtr.Zero
                    // because length of new value may depend on the contents of original
                    // one like in path modification feature
                    if (!Win32Exception.CheckIfFoundAndNoError(
                        operation(IntPtr.Zero, new Data(newpData.Ptr, newpcbData.Ptr, Data.CountIn.Bytes))))
                    {
                        return false;
                    }
                    return Win32Exception.CheckIfFoundAndNoError(
                        transformer(unchecked((Win32Api.RegValueType)type),
                            newpData.Ptr, Marshal.ReadInt32(newpcbData.Ptr)));
                }
            }
        }

        internal static bool IsStringType(Win32Api.RegValueType type)
        {
            return type == Win32Api.RegValueType.REG_SZ ||
                type == Win32Api.RegValueType.REG_MULTI_SZ ||
                type == Win32Api.RegValueType.REG_EXPAND_SZ;
        }

        internal static string PtrToString(IntPtr ptr, int nChars)
        {
            if (HookBarrier.IsLastInjectedFuncAnsi)
            {
                return Marshal.PtrToStringAnsi(ptr, nChars);
            }
            return Marshal.PtrToStringUni(ptr, nChars);
        }

        internal static string PtrToString(IntPtr ptr)
        {
            if (HookBarrier.IsLastInjectedFuncAnsi)
            {
                return Marshal.PtrToStringAnsi(ptr);
            }
            return Marshal.PtrToStringUni(ptr);
        }

        internal delegate string StringTransformer(string src);

        internal static int TransformStringValue(Win32Api.RegValueType type,
            IntPtr pSrcData, int cbSrcData,
            Data dst, StringTransformer transformer, StringFormat dstFormat)
        {
            string value = "";
            if (pSrcData != IntPtr.Zero)
            {
                value = PtrToString(pSrcData, cbSrcData / Data.BytesPerChar(dstFormat));
            }

            bool removedNullChar = false;
            if ((type == Win32Api.RegValueType.REG_SZ ||
                type == Win32Api.RegValueType.REG_EXPAND_SZ) &&
                value.EndsWith("\0"))
            {
                value = value.Remove(value.Length - 1);
                removedNullChar = true;
            }

            value = transformer(value);

            if (removedNullChar)
            {
                value += "\0";
            }

            return dst.FillWithString(new ManagedString(value), dstFormat,
                Data.NullCharHandling.NotAddingIfNotPresent);
        }
    }

    internal class DataAlterer
    {
        internal delegate string StrAlterer(KeyIdentity key, string valueName, string value);
        private List<StrAlterer> strAlterers_ = new List<StrAlterer>();

        internal void RegisterStringValueAlterer(StrAlterer alterer)
        {
            strAlterers_.Add(alterer);
        }

        private string CallStrAlterers(KeyIdentity key, string valueName, string value)
        {
            foreach (StrAlterer alterer in strAlterers_)
            {
                value = alterer(key, valueName, value);
            }
            return value;
        }

        internal bool TryAlterData(KeyIdentity key, string valueName,
            IKeyImpl keyImpl, IntPtr pdwType, Data dst, DataTransformer.Operation operation)
        {
            // TODO: this is a specific check that
            // rewrite is done only for values in sandboxie reghive which is BASE_HIVE
            // and if values are copied, DIFF_HIVE is also supported
            // It should be put outside this generalized class
            if (keyImpl.GetDisposition() == KeyDisposition.WINDOWS_REG)
            {
                return Win32Exception.CheckIfFoundAndNoError(operation(pdwType, dst));
            }
            return DataTransformer.TryAlterData(pdwType, dst, operation,
                (result, type) =>
                {
                    DebugLogger.WriteLine(@"AlterData {0} {1}\{2} ({3}) Result: {4}",
                        keyImpl.GetDisposition(), key.ToString(), valueName, type, (int)result);
                    return result == Win32Api.Error.ERROR_SUCCESS &&
                        DataTransformer.IsStringType(type);
                },
                (type, pSrcData, cbSrcData) =>
                    DataTransformer.TransformStringValue(
                        type, pSrcData, cbSrcData, dst, str => CallStrAlterers(key, valueName, str),
                        HookBarrier.IsLastInjectedFuncAnsi ? StringFormat.Ansi : StringFormat.Unicode));
        }
    }

    internal class Uni2AnsiConverter : DisposableBase
    {
        private HGlobalPtr unicodeStr_;
        private Data ansiStr_;
        private bool doConvert_;

        internal IntPtr UnicodeStr
        {
            get { return doConvert_ ? unicodeStr_.Ptr : ansiStr_.Ptr; }
        }

        // ATTENTION: pcchAnsiStr contains number of characters, NOT bytes
        internal Uni2AnsiConverter(Data ansiStr, bool doConvert = true)
        {
            ansiStr_ = ansiStr;
            doConvert_ = doConvert;
            if (!doConvert) return;
            int cchAnsiStr = 0;
            if (ansiStr.PCount!= IntPtr.Zero) cchAnsiStr = Marshal.ReadInt32(ansiStr.PCount);
            // Here using the feature of HGlobalPtr that its pointer
            // is assigned IntPtr.Zero if size passed to ctor is zero.
            unicodeStr_ = new HGlobalPtr(sizeof(char) * cchAnsiStr);
        }

        // Before calling this function please make sure that pcchAnsiStr
        // contains exactly the length of the string EXCLUDING null character
        // and that the buffer pointed by unicodeStr CONTAINS null character
        // otherwise this call will lead to buffer overrun and UB.
        internal void Convert()
        {
            if (!doConvert_) return;
            if (ansiStr_.Ptr != IntPtr.Zero)
            {
                PInvokeHelper.StringUniToAnsi(unicodeStr_.Ptr, ansiStr_.Ptr,
                    Marshal.ReadInt32(ansiStr_.PCount) + 1);
            }
        }

        protected override void DisposeManaged()
        {
            if (unicodeStr_ != null)
            {
                unicodeStr_.Dispose();
            }
        }
    }
}
