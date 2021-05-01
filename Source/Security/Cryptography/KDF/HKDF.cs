using System;

using Litdex.Security.Cryptography.Hash;
using Litdex.Security.Cryptography.MAC;
using Litdex.Security.KDF;

namespace Litdex.Security.Cryptography.KDF
{
	/// <summary>
	///		HMAC-based Key Derivation Function based on RFC 5869.
	/// </summary>
	public class HKDF : IKDF
	{
		#region Member

		private readonly IMAC _MAC;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="HKDF"/> object.
		/// </summary>
		public HKDF() : this(new SHA1())
		{

		}

		/// <summary>
		///		Create an instance of <see cref="HKDF"/> object.
		/// </summary>
		/// <param name="hash">
		///		Hash function tu use.
		///	</param>
		public HKDF(IHash hash)
		{
			this._MAC = new MAC.HMAC(hash);
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~HKDF()
		{
			this.Reset();
		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		///		Create a pseudorandom key.
		/// </summary>
		/// <param name="salt">
		///		Optional salt value.
		///	</param>
		/// <param name="InputKeyMaterial">
		///		Input key material.
		///	</param>
		/// <returns>
		///		
		/// </returns>
		private byte[] Extract(byte[] salt, byte[] InputKeyMaterial)
		{
			if (salt == null)
			{
				salt = new byte[InputKeyMaterial.Length];
				for (var i = 0; i < salt.Length; i++)
				{
					salt[i] = 0;
				}
			}

			return this._MAC.ComputeHash(salt, InputKeyMaterial);
		}

		/// <summary>
		///		Expand key.
		/// </summary>
		/// <param name="prk">
		///		A pseudorandom key.
		///	</param>
		/// <param name="info">
		///		Optional context and application specific information.
		///	</param>
		/// <param name="length">
		///		Length of output keying materials.
		///	</param>
		/// <returns>
		///		Output Keying material.
		/// </returns>
		private byte[] Expand(byte[] prk, byte[] info, int length)
		{
			if (prk.Length < this._MAC.GetHashLength())
			{
				throw new ArgumentException(
					"Pseudorandom key length is " + prk.Length +
					" lower than " + this._MAC.GetHashLength());
			}
			if (info == null)
			{
				info = Array.Empty<byte>();
			}
			if (length < 0)
			{
				throw new ArgumentException("Length can't be 0.");
			}
			if (length > this._MAC.GetHashLength() * 255)
			{
				throw new ArgumentException("Length can't exceed " + (this._MAC.GetHashLength() * 255));
			}

			var resultBlock = new byte[0];
			var result = new byte[length];
			var bytesRemaining = length;

			for (var i = 1; bytesRemaining > 0; i++)
			{
				var currentInfo = new byte[resultBlock.Length + info.Length + 1];
				Buffer.BlockCopy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
				Buffer.BlockCopy(info, 0, currentInfo, resultBlock.Length, info.Length);
				currentInfo[currentInfo.Length - 1] = (byte)i;
				resultBlock = this.Extract(prk, currentInfo);
				Buffer.BlockCopy(resultBlock, 0, result, length - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
				bytesRemaining -= resultBlock.Length;
			}
			return result;
		}

		#endregion Private Method

		#region Public Method

		/// <summary>
		///		Return the name of the algorithm the KDF implements.
		/// </summary>
		/// <returns>
		///		The algorithm name.
		/// </returns>
		public string AlgorithmName()
		{
			return "HKDF-" + this._MAC.GetHashFunction().AlgorithmName();
		}

		/// <inheritdoc/>
		public void Reset()
		{
			this._MAC.Reset();
		}


		/// <summary>
		///		Computes the derived key for specified byte array. 
		/// </summary>
		/// <param name="data">
		///		Data to derive.
		///	</param>
		/// <param name="salt">
		///		Additional byte array.
		///	</param>
		/// <param name="length">
		///		Output length.
		///	</param>
		///	<param name="info">
		///		Optional info
		/// </param>
		/// <returns>
		///		Computed byte array.
		/// </returns>
		public byte[] Derive(byte[] data, byte[] salt, byte[] info, int length)
		{
			byte[] prk = this.Extract(salt, data);
			byte[] result = this.Expand(prk, info, length);
			return result;
		}

		/// <inheritdoc/>
		public byte[] Derive(byte[] data, byte[] salt, int length)
		{
			throw new NotImplementedException();
		}

		#endregion Public
	}
}
