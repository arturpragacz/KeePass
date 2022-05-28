/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2022 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

using KeePassLib.Cryptography;
using KeePassLib.Security;

namespace KeePassLib.Keys
{
	public abstract class KcpCustomKey : IUserKey
	{
		private readonly string m_strName;

		/// <summary>
		/// Name of the provider that generated the custom key.
		/// </summary>
		public string Name
		{
			get { return m_strName; }
		}

		public abstract ProtectedBinary KeyData(PwDatabase pd);

		public KcpCustomKey(string strName)
		{
			if (strName == null) { Debug.Assert(false); throw new ArgumentNullException("strName"); }
			m_strName = strName;
		}

	}

	public class KcpSimpleCustomKey : KcpCustomKey
	{
		private ProtectedBinary m_pbKey;

		public override ProtectedBinary KeyData(PwDatabase pd)
		{
			return m_pbKey;
		}

		public KcpSimpleCustomKey(string strName, byte[] pbKeyData, bool bPerformHash) : base(strName)
		{
			Debug.Assert(pbKeyData != null); if(pbKeyData == null) throw new ArgumentNullException("pbKeyData");

			if(bPerformHash)
			{
				byte[] pbRaw = CryptoUtil.HashSha256(pbKeyData);
				m_pbKey = new ProtectedBinary(true, pbRaw);
			}
			else m_pbKey = new ProtectedBinary(true, pbKeyData);
		}

		// public void Clear()
		// {
		//	m_pbKey = null;
		// }
	}
}
