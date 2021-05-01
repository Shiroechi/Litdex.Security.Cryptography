namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		With FIPS PUB 202 a new kind of message digest was 
	///		announced which supported extendable output, 
	///		or variable hash value sizes.
	/// 
	///		This interface provides the extra method required to 
	///		support variable output on a hash implementation.
	/// </summary>
	public interface IHashExtend
	{
		/// <summary>
		///		Output the results of the final calculation 
		///		for this digest to outLen number of bytes.
		/// </summary>
		/// <param name="output">
		///		Byte array the hash value is to be copied into.
		/// </param>
		/// <param name="startIndex">
		///		Offset into the output array the hash value is to start at.
		///	</param>
		/// <param name="outputlength">
		///		Length of bytes requested.
		///	</param>
		/// <returns>
		///		The number of bytes written.
		///	</returns>
		int DoFinal(byte[] output, int startIndex, int outputlength);

		/// <summary>
		///		Start outputting the results of the final calculation for this digest. Unlike DoFinal, this method
		///		will continue producing output until the Xof is explicitly reset, or signals otherwise.
		/// </summary>
		/// <param name="output">
		///		output array to write the output bytes to.</param>
		/// <param name="startIndex">
		///		offset to start writing the bytes at.
		///	</param>
		/// <returns>
		///		the number of bytes written
		///	</returns>
		int DoOutput(byte[] output, int startIndex);

		/// <summary>
		///		Start outputting the results of the final calculation for this digest. Unlike DoFinal, this method
		///		will continue producing output until the Xof is explicitly reset, or signals otherwise.
		/// </summary>
		/// <param name="output">
		///		output array to write the output bytes to.</param>
		/// <param name="startIndex">
		///		offset to start writing the bytes at.
		///	</param>
		/// <param name="outputlength">
		///		the number of output bytes requested.
		///	</param>
		/// <returns>
		///		the number of bytes written
		///	</returns>
		int DoOutput(byte[] output, int startIndex, int outputlength);

		/// <summary>
		///		Computes the hash value for the specified region of the specified byte array.
		/// </summary>
		/// <param name="input">
		///		The array of bytes to compute the hash value for.
		///	</param>
		///	<param name="startIndex">
		///		 The offset into the byte array from which to begin using data.
		/// </param>
		/// <param name="length">
		///		The number of bytes in the array to use as data.
		/// </param>
		/// <param name="outputlength">
		///		the number of output bytes requested.
		/// </param>
		/// <returns>
		///		The computed hash code.
		/// </returns>
		///	<exception cref="System.ArgumentOutOfRangeException">
		///		Requested length can't exceed from remaining length of array after the start index.
		/// </exception>
		byte[] ComputeHash(byte[] input, int startIndex, int length, int outputlength);

	}
}
