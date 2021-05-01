using System;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of SHAKE based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// </summary>
	/// <remarks>
	///		Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </remarks>
	public class SHAKE : Keccak, IHashExtend
	{
		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="SHAKE"/> object.
		/// </summary>
		/// <param name="bitLength">
		///		Output byte.
		///	</param>
		public SHAKE(int bitLength = 256) : base(CheckBitLength(bitLength))
		{

		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~SHAKE()
		{
			this.Reset();
		}

		#endregion Constructor & Destructor

		#region Private Method

		private static int CheckBitLength(int bitLength)
		{
			switch (bitLength)
			{
				case 128:
				case 256:
					return bitLength;
				default:
					throw new ArgumentException(bitLength + " not supported for SHAKE.", "bitLength");
			}
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "SHAKE-" + this.fixedOutputLength;
		}

		/// <inheritdoc/>
		public override int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public override int DoFinal(byte[] output, int startIndex)
		{
			return this.DoFinal(output, startIndex, this.GetHashLength());
		}

		/// <inheritdoc/>
		public virtual int DoFinal(byte[] output, int startIndex, int outputlength)
		{
			this.DoOutput(output, startIndex, outputlength);

			this.Reset();

			return outputlength;
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			return this.ComputeHash(input, startIndex, length, this.GetHashLength());
		}

		/// <inheritdoc/>
		public virtual byte[] ComputeHash(byte[] input, int startIndex, int length, int outputlength)
		{
			byte[] result = new byte[outputlength];
			this.Update(input, startIndex, length);
			this.DoOutput(result, startIndex, outputlength);

			this.Reset();
			return result;
		}

		/// <inheritdoc/>
		public virtual int DoOutput(byte[] output, int startIndex)
		{
			return this.DoOutput(output, startIndex, output.Length - startIndex);
		}

		/// <inheritdoc/>
		public virtual int DoOutput(byte[] output, int startIndex, int outputlength)
		{
			if (!this.squeezing)
			{
				this.Absorb(new byte[] { 0x0F }, 0, 4);
			}

			this.Squeeze(output, startIndex, ((long)outputlength) * 8);

			return outputlength;
		}

		/// <inheritdoc/>
		public override IHash Clone()
		{
			return new SHAKE(this.fixedOutputLength);
		}

		#endregion Public Method
	}
}
