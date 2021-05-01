using System;

using Litdex.Security.Cryptography.Hash;
using Litdex.Utilities.Extension;

namespace Litdex.Security.Cryptography.MAC
{
	/// <summary>
	///		HMAC implementation based on RFC 2104.
	/// </summary>
	/// <remarks>
	///		H(K XOR opad, H(K XOR ipad, text))
	///	</remarks>
	public class HMAC : IMAC
	{
		#region Member

		private bool _Initilized;
		private const byte IPAD = 0x36;
		private const byte OPAD = 0x5C;

		private readonly IHash _Hash;

		private readonly int DigestSize;
		private readonly int BlockSize;

		private byte[] _InnerPadding;
		private byte[] _OuterPadding;
		private byte[] _KeyValue;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="HMAC"/> object.
		/// </summary>
		/// <param name="digest">
		///		Hash function to use.
		///	</param>
		public HMAC(IHash digest)
		{
			digest.Reset();
			this._Hash = digest;
			this.DigestSize = digest.GetHashLength();
			this.BlockSize = digest.GetByteLength();
			this._InnerPadding = new byte[this.BlockSize];
			this._OuterPadding = new byte[this.BlockSize/* + DigestSize*/];
			this._KeyValue = new byte[0];
			this._Initilized = false;
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~HMAC()
		{
			this._Hash.Reset();
			this._InnerPadding.Clear();
			this._OuterPadding.Clear();
			this._KeyValue.Clear();
		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		///		Initialize the MAC.
		/// </summary>
		/// <param name="key">
		///		key required by the MAC.
		///	</param>
		private void InitializeKey(byte[] key)
		{
			this._Hash.Reset();

			if (key.Length > this.BlockSize)
			{
				this._KeyValue = new byte[this._Hash.GetHashLength()];
				this._KeyValue = this._Hash.ComputeHash(key);
			}

			if (key.Length < this.BlockSize)
			{
				this._KeyValue = this.PadKey(key);
			}

			this.UpdatePad();
		}

		private void UpdatePad()
		{
			if (this._InnerPadding.Length != this.BlockSize)
			{
				this._InnerPadding.Clear();
				this._InnerPadding = new byte[this.BlockSize];
			}
			if (this._OuterPadding.Length != this.BlockSize)
			{
				this._OuterPadding.Clear();
				this._OuterPadding = new byte[this.BlockSize];
			}

			//initialize padding
			for (int i = 0; i < this.BlockSize; i++)
			{
				this._InnerPadding[i] = IPAD;
				this._OuterPadding[i] = OPAD;
			}

			//XOR padding with key
			for (int i = 0; i < this._KeyValue.Length; i++)
			{
				this._InnerPadding[i] ^= this._KeyValue[i];
				this._OuterPadding[i] ^= this._KeyValue[i];
			}
		}

		private byte[] PadKey(byte[] key)
		{
			var result = new byte[this._Hash.GetByteLength()];
			Array.Copy(key, 0, result, 0, key.Length);
			return result;
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public virtual void Initialize(byte[] key)
		{
			this.InitializeKey(key);
			this._Initilized = true;
			this._Hash.Update(this._InnerPadding);
		}

		/// <inheritdoc/>
		public virtual string AlgorithmName()
		{
			return this._Hash.AlgorithmName() + "/HMAC";
		}

		/// <inheritdoc/>
		public virtual void Reset()
		{
			// Reset underlying digest
			this._Hash.Reset();

			if (this._KeyValue == null)
			{
				this._Initilized = false;
			}
			else
			{
				this.Initialize(this._KeyValue);
			}
		}

		/// <inheritdoc/>
		public int GetHashLength()
		{
			return this._Hash.GetHashLength();
		}

		/// <inheritdoc/>
		public IHash GetHashFunction()
		{
			return this._Hash;
		}

		/// <inheritdoc/>
		protected virtual IHash GetUnderlyingDigest()
		{
			return this._Hash;
		}

		/// <inheritdoc/>
		protected virtual int GetMacSize()
		{
			return this.DigestSize;
		}

		/// <inheritdoc/>
		public void Update(byte[] input)
		{
			this.Update(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public void Update(string input)
		{
			this.Update(input.GetBytes(), 0, input.Length);
		}

		/// <inheritdoc/>
		public void Update(byte[] input, int startIndex, int length)
		{
			if (this._Initilized == false)
			{
				throw new Exception("No key to found, please initialize the HMAC first.");
			}

			this._Hash.Update(input, startIndex, length);
		}

		/// <inheritdoc/>
		public int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public int DoFinal(byte[] output, int startIndex)
		{
			// 1st pass
			this._Hash.DoFinal(output, startIndex);

			// 2nd pass
			this._Hash.Reset();
			this._Hash.Update(this._OuterPadding, 0, this._OuterPadding.Length);
			this._Hash.Update(output);
			this._Hash.DoFinal(output, startIndex);

			this.Reset();

			return this._Hash.GetHashLength();
		}

		/// <inheritdoc/>
		public byte[] ComputeHash(byte[] keys, byte[] data)
		{
			this.InitializeKey(keys);
			this._Hash.Reset();

			var result = new byte[this._Hash.GetHashLength()];

			// 1st pass
			this._Hash.Update(this._InnerPadding, 0, this._InnerPadding.Length);
			this._Hash.Update(data, 0, data.Length);
			this._Hash.DoFinal(result, 0);

			// 2nd pass
			this._Hash.Reset();
			this._Hash.Update(this._OuterPadding, 0, this._OuterPadding.Length);
			this._Hash.Update(result, 0, result.Length);
			this._Hash.DoFinal(result, 0);

			return result;
		}

		#endregion Public Method
	}
}
