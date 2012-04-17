<?php
/*
	Copyright © 2012, Akseli "Core Xii" Tarkkio <corexii@gmail.com>

	Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class Password_Hash
	{
	const DEFAULT_ALGORITHM = 'whirlpool';
	const DEFAULT_MIN_TIME = 2.0;
	const DEFAULT_MIN_ITERATIONS_LOG2 = 17;
	
	public function get_plaintext() { return $this -> plaintext; }
	public function get_hash() { return $this -> hash; }
	public function get_salt() { return $this -> salt; }
	public function get_algorithm() { return $this -> algorithm; }
	public function get_time() { return $this -> time; }
	public function get_min_time() { return $this -> min_time; }
	public function get_iterations_log2() { return $this -> iterations_log2; }
	public function get_min_iterations_log2() { return $this -> min_iterations_log2; }
	
	public function set_min_time($min_time = self::DEFAULT_MIN_TIME) { return $this -> min_time = $min_time; }
	public function set_min_iterations_log2($min_iterations_log2 = self::DEFAULT_MIN_ITERATIONS_LOG2) { return $this -> min_iterations_log2 = $min_iterations_log2; }
	
	public function set_min_requirements($min_time = self::DEFAULT_MIN_TIME, $min_iterations_log2 = self::DEFAULT_MIN_ITERATIONS_LOG2)
		{
		$this -> min_time = $min_time;
		$this -> min_iterations_log2 = $min_iterations_log2;
		}
	
	/**
		Create hash from plaintext.
		
		For additional salting, make $plaintext = $salt . 'plaintext'; (concatenate salt first to combat partial rainbow cracking)
	*/
	public function hash_plaintext($plaintext, $algorithm = self::DEFAULT_ALGORITHM, $min_time = self::DEFAULT_MIN_TIME, $min_iterations_log2 = self::DEFAULT_MIN_ITERATIONS_LOG2)
		{
		$this -> set_algorithm($algorithm);
		$this -> plaintext = $plaintext;
		$this -> generate_salt();
		$this -> hash = $this -> salt . $plaintext;
		$this -> min_time = $min_time;
		$this -> min_iterations_log2 = $min_iterations_log2;
		
		$this -> time = 0.0;
		$this -> iterations_log2 = 0;
		while ($this -> need_hashing())
			{
			$time_start = microtime(true);
			for ($i = pow(2, $this -> iterations_log2 ++); $i > 0; -- $i)
				{
				$this -> hash = hash($algorithm, $this -> hash, true);
				}
			$this -> time += microtime(true) - $time_start;
			}
		
		return $this -> serialize_to_json();
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
		$data = json_decode($data_json);
		$this -> set_algorithm($data -> algorithm);
		$this -> plaintext = null;
		self::copy_object_property($data, $this, ['hash', 'salt', 'time', 'iterations_log2']);
		}
	
	public function does_match_plaintext($plaintext)
		{
		if ($this -> plaintext !== null && $plaintext === $this -> plaintext)
			{
			return true;
			}
		if ($this -> hash === '')
			{
			throw new Exception("Can't compare plaintext without hash.");
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
		
		Must hash plaintext or unserialize before calling this method.
		
		Returns whether hashing was needed (and consequently performed).
	*/
	public function hash($algorithm = null, $min_time = null, $min_iterations_log2 = null)
		{
		if ($algorithm !== null && $algorithm !== $this -> algorithm)
			{
			if ($this -> plaintext === null)
				{
				throw new Exception("Can't re-hash with different algorithm without plaintext. Compare against plaintext first.");
				}
			
			$this -> set_algorithm($algorithm);
			$this -> generate_salt();
			$this -> hash = $this -> salt . $this -> plaintext;
			$this -> time = 0.0;
			$this -> iterations_log2 = 0;
			}
		
		if ($min_time !== null)
			{
			$this -> min_time = $min_time;
			}
		if ($min_iterations_log2 !== null)
			{
			$this -> min_iterations_log2 = $min_iterations_log2;
			}
		
		if (!$this -> need_hashing())
			{
			return false;
			}
		if ($this -> hash === '')
			{
			throw new Exception("Can't continue hashing without hash. Hash plaintext or unserialize first.");
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
			while ($this -> need_hashing());
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
		$random_binary_string = '';
		for ($i = $length; $i > 0; -- $i)
			{
			$random_binary_string .= chr(mt_rand(0, 255));
			}
		return $random_binary_string;
		}
	
	private static function copy_object_property(object $source_object, object $target_object, $property_names)
		{
		if (is_string($property_names))
			{
			$property_names = [$property_names];
			}
		
		$i = 0;
		foreach ($property_names as $source_property_name => $target_property_name)
			{
			if (!is_string($source_property_name))
				{
				$source_property_name = $target_property_name;
				}
			
			if (!isset($source_object -> {$source_property_name}))
				{
				throw new Exception("Source object doesn't have property " . $source_property_name . '.');
				}
			if (!isset($target_object -> {$target_property_name}))
				{
				throw new Exception("Target object doesn't have property " . $target_property_name . '.');
				}
			
			$target_object -> {$target_property_name} = $source_object -> {$target_property_name};
			++ $i;
			}
		return $i;
		}
	
	private function set_algorithm($algorithm)
		{
		if (!in_array($algorithm, hash_algos()))
			{
			throw new Exception('Hash algorithm ' . $algorithm . " isn't supported.");
			}
		
		$this -> algorithm = $algorithm;
		}
	
	private function generate_salt()
		{
		$this -> salt = self::random_binary_string(strlen(hash($this -> algorithm, '', true)));
		}
	}