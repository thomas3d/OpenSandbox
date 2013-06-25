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
using System.IO;
using System.Xml;

namespace OpenSandbox
{
    internal class Params
    {
        private XmlDocument doc_ = new XmlDocument();

        public Params(string xml)
        {
            doc_.LoadXml(xml);
        }

        private XmlElement TakeOneElement(XmlElement node, string name)
        {
            XmlNodeList nodes = node.GetElementsByTagName(name);
            if (nodes.Count != 1)
                throw new ApplicationException("No or too many nodes with name " + name);
            return (XmlElement)nodes.Item(0);
        }

        public string GetRegHivePath()
        {
            return TakeOneElement(doc_.DocumentElement, "reghive").InnerText;
        }

        public uint GetThreadId()
        {
            return Convert.ToUInt32(TakeOneElement(doc_.DocumentElement, "threadId").InnerText);
        }

        public uint GetRedmineId()
        {
            return Convert.ToUInt32(TakeOneElement(doc_.DocumentElement, "redmineId").InnerText);
        }

        public bool IsProductionTitle()
        {
            return TakeOneElement(doc_.DocumentElement, "production").InnerText == "true";
        }

        public string GetCryptoKey()
        {
            return TakeOneElement(doc_.DocumentElement, "keyString").InnerText;
        }
    }
}
