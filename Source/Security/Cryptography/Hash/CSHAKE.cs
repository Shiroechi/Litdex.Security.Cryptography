using System;

using Litdex.Utilities;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Customizable SHAKE function.
	/// </summary>
	internal class CSHAKE : SHAKE
	{
		#region Member

		private static readonly byte[] padding = new byte[100];

		private static byte[] EncodeString(byte[] str)
		{
			if (str == null || str.Length < 1)
			{
				return XofUtilities.LeftEncode(0L);
			}

			byte[] concat = new byte[str.Length * 8L + str.Length];
			var a = XofUtilities.LeftEncode(str.Length * 8L);
			Array.Copy(a, 0, concat, 0, a.Length);
			Array.Copy(str, 0, concat, a.Length, str.Length);
			return concat;
		}

		private readonly byte[] diff;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="CSHAKE"/> object.
		/// </summary>
		/// <param name="bitLength">
		///		bit length of the underlying SHAKE function, 128 or 256.
		///	</param>
		/// <param name="N">
		///		the function name string, note this is reserved for use by NIST. Avoid using it if not required.
		///	</param>
		/// <param name="S">
		///		the customization string - available for local use.
		///	</param>
		public CSHAKE(int bitLength = 256, byte[] N = null, byte[] S = null) : base(bitLength)
		{
			if ((N == null || N.Length == 0) && (S == null || S.Length == 0))
			{
				this.diff = null;
			}
			else
			{
				this.diff = ConcatenateAll(XofUtilities.LeftEncode(this.rate / 8), EncodeString(N), EncodeString(S));
				this.DiffPadAndAbsorb();
			}
		}

		#endregion Constructor & Destructor

		#region Private Method

		// bytepad in SP 800-185
		private void DiffPadAndAbsorb()
		{
			int blockSize = this.rate / 8;
			this.Absorb(this.diff, 0, this.diff.Length);

			int delta = this.diff.Length % blockSize;

			// only add padding if needed
			if (delta != 0)
			{
				int required = blockSize - delta;

				while (required > padding.Length)
				{
					this.Absorb(padding, 0, padding.Length);
					required -= padding.Length;
				}

				this.Absorb(padding, 0, required);
			}
		}

		private static byte[] ConcatenateAll(params byte[][] vs)
		{
			byte[][] nonNull = new byte[vs.Length][];
			int count = 0;
			int totalLength = 0;

			for (int i = 0; i < vs.Length; ++i)
			{
				byte[] v = vs[i];
				if (v != null)
				{
					nonNull[count++] = v;
					totalLength += v.Length;
				}
			}

			byte[] result = new byte[totalLength];
			int pos = 0;

			for (int j = 0; j < count; ++j)
			{
				byte[] v = nonNull[j];
				Array.Copy(v, 0, result, pos, v.Length);
				pos += v.Length;
			}

			return result;
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "CSHAKE-" + this.fixedOutputLength;
		}

		/// <inheritdoc/>
		public override void Reset()
		{
			base.Reset();

			if (this.diff != null)
			{
				this.DiffPadAndAbsorb();
			}
		}

		/// <inheritdoc/>
		public override int DoOutput(byte[] output, int startIndex, int outputlength)
		{
			if (this.diff == null)
			{
				return base.DoOutput(output, startIndex, outputlength);
			}

			if (!this.squeezing)
			{
				// TODO fix error
				this.Absorb(new byte[] { 0x00 }, 0, 4);
				//	AbsorbBits(0x00, 2);
			}

			this.Squeeze(output, startIndex, ((long)outputlength) << 3);

			return outputlength;
		}

		#endregion Public Method

	}
}
