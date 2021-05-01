namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Interface structure of hash fuction.
	/// </summary>
	public interface IHash
	{
		/// <summary>
		///		Hash algorithm name.
		/// </summary>
		/// <returns>
		///		The hash algorithm name.
		/// </returns>
		string AlgorithmName();

		/// <summary>
		///		Reset the hash function back to it's initial state.
		/// </summary>
		void Reset();

		/// <summary>
		///		Return the size (in <see cref="byte"/>) of the final hash produced by this hash function.
		/// </summary>
		/// <returns>
		///		The hash length.
		/// </returns>
		int GetHashLength();

		/// <summary>
		///		Return the size (in <see cref="byte"/>) of this hash function internal state.
		/// </summary>
		/// <returns>
		///		The internal state size.
		/// </returns>
		int GetByteLength();

		/// <summary>
		///		Computes the hash value for the specified input byte.
		/// </summary>
		/// <param name="input">
		///		The input to compute the hash code for.
		/// </param>
		void Update(byte input);

		/// <summary>
		///		Computes the hash value for the specified input byte array.
		/// </summary>
		/// <param name="input">
		///		The input to compute the hash code for.
		/// </param>
		void Update(byte[] input);

		/// <summary>
		///		Computes the hash value for the specified input byte array.
		/// </summary>
		/// <param name="input">
		///		The input to compute the hash code for.
		///	</param>
		/// <param name="startIndex">
		///		The start index into the input byte array from which to begin using data.
		///	</param>
		/// <param name="length">
		///		The number of bytes in the array to use as data.
		///	</param>
		///	<exception cref="System.ArgumentOutOfRangeException">
		///		Requested length can't exceed from remaining length of array after the start index.
		/// </exception>
		void Update(byte[] input, int startIndex, int length);

		/// <summary>
		///		Copy final hash value to <paramref name="output"/> array and reset the hash function.
		/// </summary>
		/// <param name="output">
		///		The computed hash code.
		///	</param>
		/// <returns>
		///		Size of computed hash code.
		/// </returns>
		int DoFinal(byte[] output);

		/// <summary>
		///		Copy final hash value to <paramref name="output"/> array and reset the hash function.
		/// </summary>
		/// <param name="output">
		///		The computed hash code.
		///	</param>
		///	<param name="startIndex">
		///		The offset into the <paramref name="output"/> array from which index to begin copy the computed hash value..
		/// </param>
		/// <returns>
		///		Size of computed hash code.
		/// </returns>
		int DoFinal(byte[] output, int startIndex);

		/// <summary>
		///		Computes the hash value from <paramref name="input"/> array.
		/// </summary>
		/// <param name="input">
		///		The array of bytes to compute the hash value for.
		///	</param>
		/// <returns>
		///		The computed hash code.
		/// </returns>
		byte[] ComputeHash(byte[] input);

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
		/// <returns>
		///		The computed hash code.
		/// </returns>
		///	<exception cref="System.ArgumentOutOfRangeException">
		///		Requested length can't exceed from remaining length of array after the start index.
		/// </exception>
		byte[] ComputeHash(byte[] input, int startIndex, int length);

		/// <summary>
		///		Create clone of current object.
		/// </summary>
		/// <returns>
		///		Return a deep copy of this object.
		/// </returns>
		IHash Clone();
	}
}
