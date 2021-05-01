using System;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// </summary>
	/// <remarks>
	///		Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </remarks>
	public class SHA3 : Keccak
	{
		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="SHA3"/> object.
		/// </summary>
		/// <param name="bitLength">
		///		Hash value length.
		///	</param>
		public SHA3(int bitLength = 512) : base(CheckBitLength(bitLength))
		{

		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~SHA3()
		{
			this.Reset();
		}

		#endregion Constructor & Destructor

		#region Private Method

		private static int CheckBitLength(int bitLength)
		{
			switch (bitLength)
			{
				case 224:
				case 256:
				case 384:
				case 512:
					return bitLength;
				default:
					throw new ArgumentException(bitLength + " not supported for SHA-3", "bitLength");
			}
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "SHA3-" + this.fixedOutputLength;
		}

		/// <inheritdoc/>
		public override int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public override int DoFinal(byte[] output, int startIndex)
		{
			this.Absorb(new byte[] { 0x02 }, 0, 2);
			return base.DoFinal(output, startIndex);
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			var result = new byte[this.GetHashLength()];
			this.Update(input, startIndex, length);
			this.DoFinal(result, 0);
			return result;
		}

		/// <inheritdoc/>
		public override IHash Clone()
		{
			return new SHA3(this.fixedOutputLength);
		}

		#endregion Public Method
	}
}
