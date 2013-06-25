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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle("OpenSandbox")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("OpenSandbox")]
[assembly: AssemblyCopyright("Copyright © 2013")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("a66c07bb-6935-4e67-bb5d-e18da28ce543")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Revision and Build Numbers 
// by using the '*' as shown below:
[assembly: AssemblyVersion("3.3.2.0")]
[assembly: AssemblyFileVersion("3.3.2.0")]

[assembly: InternalsVisibleTo("SandboxTests, PublicKey=002400000480000094000000060200000024000052534131000400000100010045af4f84ff41d6" +
"0e37656b5440ab45044635e6993142b3a8389e31fe1e7f1a93659659d82776d609b0c7c50eb6c7" +
"b729f2b974ad9f76f177d951d082158d0ad1deab6bb33c81c45b90707f7777e7c6931a74c710b5" +
"88408547c70942fbe44952434b3abb17a57c1d09b75880071762415b0b0f90678a1ad9b34bc411" +
"02c281db")]

[assembly: InternalsVisibleTo("AppUnderTest, PublicKey=0024000004800000940000000602000000240000525341310004000001000100f5715ea0f21340" +
"bf39d8df19c4146ea9a1123ceef237e0f9ca9c7dd1a5ba48bda81306d67f70d575d7f7b7f8c0c3" +
"6121a05be6c0bf7548529131e37a9d624bc3947cc7cda11117ec5452c8780debaa54b72685a308" +
"e2777cfd083f63e1e8c2d0233498a87a0abda5f5c26bc27bb961571437bf2474d3debdb5bc1054" +
"ca85aa8b")]

[assembly: InternalsVisibleTo("TestUtils, PublicKey=00240000048000009400000006020000002400005253413100040000010001000351b2b900df61" +
"9612b5006b7cdeaf0f185e1bcd3e9bf2d11787caefc69f9eef61e07ca21ef1d317e6532457d295" +
"16732282aba02dd265990de8ec7cbfa94f4bf0f26b447a0b9035ea80e31f29eae5aeb3b2dd59ea" +
"15aca46e77aa49656f2465c3738cf5a5fa6f1932369021cb37b32f71f0c7e62444fb7ed0d1ea0d" +
"de3cb4a1")]
