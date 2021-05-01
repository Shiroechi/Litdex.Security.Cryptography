using System;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Base implementation of MD4 family style digest as outlined in
	///		"Handbook of Applied Cryptography", pages 344 - 347.
	/// </summary>
	public abstract class BaseSHA : IHash
	{
		#region Member

		protected byte DigestLength = 0;
		protected byte ByteLength = 64;

		protected byte[] xBuf = new byte[4];
		protected int xBufOff;

		protected long[] byteCount = new long[1];

		#endregion Member

		#region Private Method

		internal abstract void ProcessWord(byte[] input, int startIndex);

		internal abstract void ProcessLength(long bitLength);

		internal abstract void ProcessBlock();

		internal virtual void Finish()
		{
			var bitLength = this.byteCount[0] << 3;

			//
			// add the pad bytes.
			//
			this.Update(128);

			while (this.xBufOff != 0)
			{
				this.Update(0);
			}

			this.ProcessLength(bitLength);
			this.ProcessBlock();
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public abstract string AlgorithmName();

		/// <inheritdoc/>
		public virtual void Update(byte input)
		{
			this.xBuf[this.xBufOff++] = input;

			if (this.xBufOff == this.xBuf.Length)
			{
				this.ProcessWord(this.xBuf, 0);
				this.xBufOff = 0;
			}

			this.byteCount[0]++;
		}

		/// <inheritdoc/>
		public virtual void Update(byte[] input)
		{
			this.Update(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public virtual void Update(byte[] input, int startIndex, int length)
		{
			if (length > input.Length - startIndex)
			{
				throw new ArgumentOutOfRangeException(nameof(length), "Requested length can't exceed from remaining length of array after the start index.");
			}

			//
			// fill the current word
			//
			var i = 0;
			if (this.xBufOff != 0)
			{
				while (i < length)
				{
					this.xBuf[this.xBufOff++] = input[startIndex + i++];
					if (this.xBufOff == 4)
					{
						this.ProcessWord(this.xBuf, 0);
						this.xBufOff = 0;
						break;
					}
				}
			}

			//
			// process whole words.
			//
			int limit = ((length - i) & ~3) + i;
			for (; i < limit; i += 4)
			{
				this.ProcessWord(input, startIndex + i);
			}

			//
			// load in the remainder.
			//
			while (i < length)
			{
				this.xBuf[this.xBufOff++] = input[startIndex + i++];
			}

			this.byteCount[0] += length;
		}

		/// <inheritdoc/>
		public virtual int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public abstract int DoFinal(byte[] output, int startIndex);

		/// <inheritdoc/>
		public virtual byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public abstract byte[] ComputeHash(byte[] input, int startIndex, int length);

		/// <inheritdoc/>
		public virtual void Reset()
		{
			this.byteCount[0] = 0;
			this.xBufOff = 0;
			Array.Clear(this.xBuf, 0, this.xBuf.Length);
		}

		/// <inheritdoc/>
		public abstract int GetHashLength();

		/// <inheritdoc/>
		public virtual int GetByteLength()
		{
			return this.ByteLength;
		}

		/// <inheritdoc/>
		public abstract IHash Clone();

		#endregion Public Method
	}
}
