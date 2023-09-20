<?php
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 */

namespace BLKTech\Cryptography;

use BLKTech\FileSystem\File;
use BLKTech\Cryptography\Exception\InvalidHashValueException;
use BLKTech\Cryptography\Exception\HashAlgorithmCalcException;
use BLKTech\Cryptography\Exception\HashAlgorithmNotFoundException;

/**
 *
 * @author TheKito < blankitoracing@gmail.com >
 */

class Hash
{
    public static function getAlgorithms()
    {
        return hash_algos();
    }

    public static function getAlgorithm($name)
    {
        $lowerName = strtolower($name);

        static $_ = null;

        if($_ === null) {
            $_ = array();
        }

        if(!isset($_[$lowerName])) {
            $_[$lowerName] = new Hash($lowerName);
        }

        return $_[$lowerName];
    }


    private $name;
    private $example;
    private function __construct($name)
    {
        $this->name = $name;

        if(!in_array($this->name, self::getAlgorithms())) {
            throw new HashAlgorithmNotFoundException($this->name);
        }

        $this->example = $this->calc('');
    }

    public function calc($data)
    {
        $t = hash($this->name, $data);

        if($t === false) {
            throw new HashAlgorithmCalcException($data);
        }

        return strtoupper($t);
    }

    public function calcFile(File $file)
    {
        $t = hash_file($this->name, $file->__toString());

        if($t === false) {
            throw new HashAlgorithmCalcException($file->__toString());
        }

        return strtoupper($t);
    }

    public function check($hashValue, $data)
    {
        return $this->calc($data) == strtoupper($hashValue);
    }

    public function checkFile($hashValue, File $file)
    {
        return $this->calcFile($file) == strtoupper($hashValue);
    }

    public function checkHash($hashValue)
    {
        return strlen($hashValue) == strlen($this->example);
    }

    public function validateHash($hashValue)
    {
        if(!$this->checkHash($hashValue)) {
            throw new InvalidHashValueException($hashValue);
        }
    }

    public function getName()
    {
        return $this->name;
    }


}
