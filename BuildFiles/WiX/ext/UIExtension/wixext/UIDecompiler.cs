//-------------------------------------------------------------------------------------------------
// <copyright file="UIDecompiler.cs" company="Microsoft">
//    Copyright (c) Microsoft Corporation.  All rights reserved.
//    
//    The use and distribution terms for this software are covered by the
//    Common Public License 1.0 (http://opensource.org/licenses/cpl.php)
//    which can be found in the file CPL.TXT at the root of this distribution.
//    By using this software in any fashion, you are agreeing to be bound by
//    the terms of this license.
//    
//    You must not remove this notice, or any other, from this software.
// </copyright>
// 
// <summary>
// The decompiler for the Windows Installer XML Toolset UI Extension.
// </summary>
//-------------------------------------------------------------------------------------------------

namespace Microsoft.Tools.WindowsInstallerXml.Extensions
{
    using System;
    using System.Collections;
    using System.Diagnostics;
    using System.Globalization;

    using Wix = Microsoft.Tools.WindowsInstallerXml.Serialize;

    /// <summary>
    /// The decompiler for the Windows Installer XML Toolset UI Extension.
    /// </summary>
    public sealed class UIDecompiler : DecompilerExtension
    {
        private bool removeLibraryRows;

        /// <summary>
        /// Gets the option to remove the rows from this extension's library.
        /// </summary>
        /// <value>The option to remove the rows from this extension's library.</value>
        public override bool RemoveLibraryRows
        {
            get { return this.removeLibraryRows; }
        }

        /// <summary>
        /// Called at the beginning of the decompilation of a database.
        /// </summary>
        /// <param name="tables">The collection of all tables.</param>
        public override void InitializeDecompile(TableCollection tables)
        {
            Table propertyTable = tables["Property"];

            if (null != propertyTable)
            {
                foreach (Row row in propertyTable.Rows)
                {
                    if ("WixUI_Mode" == (string)row[0])
                    {
                        Wix.UIRef uiRef = new Wix.UIRef();

                        uiRef.Id = String.Concat("WixUI_", (string)row[1]);

                        this.Core.RootElement.AddChild(uiRef);
                        this.removeLibraryRows = true;

                        break;
                    }
                }
            }
        }
    }
}
