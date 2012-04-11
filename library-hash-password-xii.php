<?php
/*
	Copyright © 2012, Akseli "Core Xii" Tarkkio <corexii@gmail.com>

	Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class Password_Hash
	{
	public function get_plaintext() { return $this -> plaintext; }
	public function get_algorithm() { return $this -> algorithm; }
	public function get_time() { return $this -> time; }
	public function get_min_time() { return $this -> min_time; }
	public function get_iterations_log2() { return $this -> iterations_log2; }
	public function get_min_iterations_log2() { return $this -> min_iterations_log2; }
	
	public function set_plaintext($plaintext)
		{
		$this -> hash = '';
		$this -> salt = '';
		$this -> time = 0.0;
		$this -> iterations_log2 = 0;
		
		return $this -> plaintext = $plaintext;
		}
	
	public function set_algorithm($algorithm)
		{
		if (!in_array($algorithm, hash_algos()))
			{
			throw new Exception('Hash algorithm ' . $algorithm . " isn't supported.");
			}
		
		$this -> hash = '';
		$this -> time = 0.0;
		$this -> iterations_log2 = 0;
		
		return $this -> algorithm = $algorithm;
		}
	
	public function set_min_time($min_time) { return $this -> min_time = $min_time; }
	public function set_min_iterations_log2($min_iterations_log2) { return $this -> min_iterations_log2 = $min_iterations_log2; }
	
	public function generate_salt()
		{
		if ($this -> algorithm === '')
			{
			throw new Exception("Can't generate salt without setting the algorithm first.");
			}
		
		$this -> salt = self::random_binary_string(strlen(hash($this -> algorithm, '', true)));
		}
	
	/**
		Create hash from plaintext.
		
		For additional salting, make $plaintext = $salt . 'plaintext'; (concatenate salt first to combat partial rainbow cracking)
	*/
	public function hash_plaintext($plaintext, $algorithm = 'whirlpool', $min_time = 2.0, $min_iterations_log2 = 17)
		{
		$this -> set_plaintext($plaintext);
		$this -> set_algorithm($algorithm);
		$this -> set_min_time($min_time);
		$this -> set_min_iterations_log2($min_iterations_log2);
		$this -> generate_salt();
		$this -> hash = $this -> salt . $plaintext;
		
		$this -> hash();
		}
	
	public function serialize_to_json()
		{
		return json_encode
			([
			'hash'            => $this -> hash,
			'salt'            => $this -> salt,
			'algorithm'       => $this -> algorithm,
			'time'            => $this -> time,
			'iterations_log2' => $this -> iterations_log2,
			]);
		}
	
	public function unserialize_from_json($data_json)
		{
		$this -> plaintext = null;
		$this -> copy_object_property(json_decode($data_json), ['hash', 'salt', 'algorithm', 'time', 'iterations_log2']);
		}
	
	public function does_match_plaintext($plaintext)
		{
		if ($this -> plaintext !== null && $plaintext === $this -> plaintext)
			{
			return true;
			}
		
		$hash = $this -> salt . $plaintext;
		$time_start = microtime(true);
		for ($i = pow(2, $this -> iterations_log2); $i > 0; -- $i)
			{
			$hash = hash($this -> algorithm, $hash, true);
			}
		$this -> time = microtime(true) - $time_start;
		
		if ($hash === $this -> hash)
			{
			$this -> plaintext = $plaintext;
			return true;
			}
		return false;
		}
	
	public function need_hashing()
		{
		return ($this -> iterations_log2 < $this -> min_iterations_log2 || $this -> time < $this -> min_time);
		}
	
	/**
		Hash until minimum requirements are met.
		
		Returns whether hashing was needed (and consequently performed).
	*/
	public function hash()
		{
		if (!$this -> needs_more_hashing())
			{
			return false;
			}
		do
			{
			$time_start = microtime(true);
			for ($i = pow(2, $this -> iterations_log2 ++); $i > 0; -- $i)
				{
				$this -> hash = hash($this -> algorithm, $this -> hash, true);
				}
			$this -> time += microtime(true) - $time_start;
			}
			while ($this -> needs_more_hashing());
		return true;
		}
	
	private $plaintext = null;
	private $hash = '';
	private $salt = '';
	private $algorithm = '';
	private $time = 0.0;
	private $min_time = 0.0;
	private $iterations_log2 = 0;
	private $min_iterations_log2 = 0;
	
	private static function random_binary_string($length)
		{
		$string = '';
		for ($i = $length; $i > 0; -- $i)
			{
			$string .= chr(mt_rand(0, 255));
			}
		return $string;
		}
	
	private function copy_object_property(object $object_source, $property_names)
		{
		if (is_string($property_names))
			{
			$property_names = [$property_names];
			}
		$i = 0;
		foreach ($property_names as $property_name)
			{
			if (!isset($this -> {$property_name}))
				{
				throw new Exception("Object doesn't have property named " . $property_name);
				}
			$this -> {$property_name} = $object_source -> {$property_name};
			++ $i;
			}
		return $i;
		}
	}