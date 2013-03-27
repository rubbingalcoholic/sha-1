/**
 * Streaming SHA1 MooTools Class
 *
 *
 * Copyright (c) 2013, Rubbing Alcoholic. (http://rubbingalcoholic.com)
 * 
 * Licensed under The MIT License. 
 * Redistributions of files must retain the above copyright notice.
 * 
 * @copyright	Copyright (c) 2013, Rubbing Alcoholic. (http://rubbingalcoholic.com)
 * @license		http://www.opensource.org/licenses/mit-license.php
 */
var sha1 = new Class({
	buffer: [],
	h: [],
	processed_length: 0,

	/**
	 *	Init function
	 */
	initialize: function()
	{
		this.clear();
	},

	/**
	 *	Initialize class values
	 */
	clear: function()
	{
		this.h = [
			0x67452301,
			0xEFCDAB89,
			0x98BADCFE,
			0x10325476,
			0xC3D2E1F0
		];
		this.buffer = [];
		this.processed_length = 0;
	},

	/**
	 *	Hashes data into the SHA1 class instance.
	 *	
	 *	@param string data						Data to hash
	 *
	 *	@param object options					Optional options object (descriptions of parameters below)											
	 *
	 *	@param boolean options.stream			(default false) Whether to use streaming mode. In streaming
	 *											mode, you can repeatedly hash data into the SHA1 object.
	 *											The hash will not be finalized and returned until you call
	 *											sha1.finalize(). Streaming mode is useful when you have to
	 *											hash a huge amount of data and you don't want to store all
	 *											of it in memory at one time.
	 *
	 *	@param boolean options.return_binstring	(default false) If true, returns a binary string instead
	 *											of a hexadecimal string.
	 *
	 *	@return mixed							A string if streaming mode is turned off. Otherwise void.
	 */
	hash: function(data, options)
	{
		options || (options = {});
		options.stream || (options.stream = false);

		var _to_bytes = convert.to_bytes;

		if (typeof data == 'string')
			data = _to_bytes(data);

		var _buffer 			= this.buffer.concat(data);
		var _processed_length 	= this.processed_length;

		for (var i=0; (i+64) <= _buffer.length; i += 64)
		{
			var h = this.h, a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], w = convert.to_words(_buffer.slice(i, i+64));

			for (var t = 0; t < 80; t++)
			{
				if (t >= 16)
				{
					var _wt = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
					w[t] = (_wt << 1) | (_wt >>> 31);
				}
			
				var temp = ((a << 5) | (a >>> 27)) + e + w[t];
				if (t < 20)
					temp += ((b & c) | (~b & d)) + 0x5A827999;
				else if (t < 40)
					temp += (b ^ c ^ d) + 0x6ed9eba1;
				else if (t < 60)
					temp += ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
				else // if (t < 80)
					temp += (b ^ c ^ d) + 0xCA62C1D6;

				var e = d, d = c, c = (b << 30) | (b >>> 2), b = a, a = temp;
			}

			this.h = [
				h[0] + a,
				h[1] + b,
				h[2] + c,
				h[3] + d,
				h[4] + e
			];

			_processed_length += 512;
		}

		this.buffer 			= _buffer.slice(i);
		this.processed_length	= _processed_length;
		
		if (options.stream == false)
			return this.finalize(options);
	},

	/**
	 *	Finalizes the hash by applying padding and returns the result.
	 *	This is called internally by sha1.hash() if streaming mode is turned off.
	 *	It should be called explicitly when using streaming mode after all data
	 *	is passed into sha1.hash().
	 *	
	 *	@param boolean options.return_binstring	(default false) If true, returns a binary string instead
	 *											of a hexadecimal string.
	 *
	 *	@return string							The SHA1 hash
	 */
	finalize: function(options)
	{
		options || (options = {});
		options.return_binstring || (options.return_binstring = false);

		// DO FINALIZE
		var final_length = this.processed_length + (this.buffer.length * 8);

		this.buffer.push(128);		// 10000000 to begin padding

		// Pad the buffer out to (512 - 64) bits
		for (var i=0; (this.buffer.length + 8) % 64 != 0; i++)
			this.buffer.push(0);

		// Add our 64 bit length value to the end of the buffer
		var final_binary = final_length.toString(2);

		for (var i=0; final_binary.length % 64 != 0; i++)
			final_binary = '0' + final_binary;

		this.buffer = this.buffer.concat(convert.word_to_bytes(parseInt(final_binary.substr(0, 32), 2)));
		this.buffer = this.buffer.concat(convert.word_to_bytes(parseInt(final_binary.substr(32), 2)));
		
		// Hash our padded final buffer in streaming mode
		this.hash([], {stream: true});

		var binstring = convert.words_to_binstring(this.h);

		return options.return_binstring == false ? convert.binstring_to_hex(binstring) : binstring;
	}
});

/**
 * Data Conversion Utilities:
 * This is a grab bag of functions for various types of data conversion operations
 *
 *
 * Copyright (c) 2013, Rubbing Alcoholic. (http://rubbingalcoholic.com)
 * 
 * Licensed under The MIT License. 
 * Redistributions of files must retain the above copyright notice.
 * 
 * @copyright	Copyright (c) 2013, Rubbing Alcoholic. (http://rubbingalcoholic.com)
 * @license		http://www.opensource.org/licenses/mit-license.php
 */
var convert = {
	/**
	 *	Converts a string to an array of bytes
	 *	
	 *	@param string str		The input string
	 *	@return array			The byte array
	 */
	to_bytes: function(str)
	{
		var bytes = [];

		for (var i = 0; i < str.length; i++)
			bytes.push(str.charCodeAt(i) & 255);
		
		return bytes;
	},

	/**
	 *	Converts a string or byte array to an array of "words" (32-bit integers)
	 *	(RA NOTE ~ Assumes the input string length is a multiple of 4)
	 *
	 *	@param mixed data		The input string or array
	 *	@return array			An array of 32-bit integers
	 */
	to_words: function(data)
	{
		var words		= [];
		var _to_word 	= this.to_word;

		if (typeof data != 'string')
			for (var i=0; i<data.length; i+=4)
				words.push(_to_word(data[i], data[i+1], data[i+2], data[i+3]));
		else
			for (var i=0; i<data.length; i+=4)
				words.push(_to_word(data.charCodeAt(i), data.charCodeAt(i+1), data.charCodeAt(i+2), data.charCodeAt(i+3)));

		return words;
	},

	/**
	 *	Joins up to 4 arbitrary 8 bit integer bytes into one 32 bit integer
	 *	- or -
	 *	Turns 1 binary string byte into a 32 bit integer
	 *
	 *	@param string binbyte	(optional) 1 binary string byte
	 *	@param integer byte1	(optional) Most significant byte
	 *	@param integer byte2	(optional) Second most significant byte
	 *	@param integer byte3	(optional) Third most significant byte
	 *	@param integer byte4	(optional) Least significant byte
	 *	@return integer			A 32 bit integer
	 */
	to_word: function()
	{
		if (arguments.length == 4)
			return ((arguments[0] & 255) << 24) | ((arguments[1] & 255) << 16) | ((arguments[2] & 255) << 8) | (arguments[3] & 255);
		else if (typeof arguments[0] == 'string')
			return this.to_words(arguments[0]).shift();

		var joined 	= 0;	
		for (var i = arguments.length-1; i >= 0; i--)
			joined |= (arguments[i] & 255) << 8*(arguments.length-1-i);
		
		return joined; 
	},

	/**
	 *	Converts an array of 32 bit integers to a binary string
	 *
	 *	@param array words		Input words array
	 *	@return string			Output binstring
	 */
	words_to_binstring: function(words)
	{
		var binary 				= '';
		var _word_to_binstring	= this.word_to_binstring;

		for (var i = 0; i < words.length; i++)
			binary += _word_to_binstring(words[i]);

		return binary;
	},

	/**
	 *	Converts a 32 bit integer to a 4 byte binary string
	 *
	 *	@param integer word		Input word
	 *	@return string			Output binstring
	 */
	word_to_binstring: function(word)
	{
		return 		String.fromCharCode((word >>> 24) & 255)
				+ 	String.fromCharCode((word >>> 16) & 255)
				+ 	String.fromCharCode((word >>> 8) & 255)
				+	String.fromCharCode(word & 255);
	},

	/**
	 *	Splits a 32 bit integer to an array of four 8 bit integers
	 *
	 *	@param integer word		Input word
	 *	@param array			Output byte array
	 */
	word_to_bytes: function(word)
	{
		return [
			((word >>> 24) & 255),
			((word >>> 16) & 255),
			((word >>> 8) & 255),
			(word & 255)
		];
	},

	/**
	 *	Converts a hex string to a binary string
	 *	
	 *	@param string hex		The input string
	 *	@return string			A binary string
	 */
	hex_to_binstring: function(hex)
	{
		if (hex.length % 2 == 1)
			hex = '0'+hex;

		var binary = '';

		for (var i = 0; i < hex.length; i += 2)
			binary += String.fromCharCode(parseInt(hex.substr(i, 2),16));

		return binary;
	},

	/**
	 *	Converts a binary string to a hex string
	 *	
	 *	@param string str		The input string
	 *	@return string			A hex string
	 */
	binstring_to_hex: function(str)
	{
		var hex = '';
		for (var i=0; i < str.length; i++)
			hex += (str.charCodeAt(i).toString(16).length == 1 ? '0' : '') + str.charCodeAt(i).toString(16);
		
		return hex;
	},

	/**
	 *	Base64 Encoder / Decoder object
	 */
	base64:
	{
		chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',

		/**
		 *	Encodes data into Base64 format string
		 *
		 *	@param string data
		 *	@return string
		 */
		encode: function(data)
		{
			var output = '';
			for (i=0, c=data.length; i<c; i += 3)
			{
				var char1 = data.charCodeAt(i) >> 2;
				var char2 = ((data.charCodeAt(i) & 3) << 4) | data.charCodeAt(i+1) >> 4;
				var char3 = ((data.charCodeAt(i+1) & 15) << 2) | data.charCodeAt(i+2) >> 6;
				var char4 = data.charCodeAt(i+2) & 63;

				output 	+= 	this.chars.charAt(char1)
						+ 	this.chars.charAt(char2)
						+	this.chars.charAt(char3)
						+	this.chars.charAt(char4);
			}
			if (c % 3 == 1)
				output = output.substr(0, output.length - 2) + '==';
			else if (c % 3 == 2)
				output = output.substr(0, output.length - 1) + '=';
			
			return output;
		},

		/**
		 *	Decodes data from Base64 format string into plaintext
		 *
		 *	@param string str
		 *	@return string
		 */
		decode: function(str)
		{
			var data = '';

			for (i=0, c=str.length; i<c; i += 4)
			{
				var char1 = this.chars.indexOf(str.charAt(i));
				var char2 = this.chars.indexOf(str.charAt(i+1));
				var char3 = this.chars.indexOf(str.charAt(i+2));
				var char4 = this.chars.indexOf(str.charAt(i+3));

				data += String.fromCharCode(char1 << 2 | char2 >> 4);
				if (char3 != -1)
					data += String.fromCharCode((char2 & 15) << 4 | char3 >> 2)
				if (char4 != -1)
					data += String.fromCharCode((char3 & 3) << 6 | char4);
			}
			return data;
		}
	}
}