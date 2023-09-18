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

/**
 *
 * @author TheKito < blankitoracing@gmail.com >
 */

class Crypt
{
    public static function getAlgorithms()
    {
        static $ciphers = null;

        if($ciphers===null) {
            $ciphers = openssl_get_cipher_methods();

            //ECB mode should be avoided
            $ciphers = array_filter($ciphers, function ($n) { return stripos($n, "ecb")===false; });

            //At least as early as Aug 2016, Openssl declared the following weak: RC2, RC4, DES, 3DES, MD5 based
            $ciphers = array_filter($ciphers, function ($c) { return stripos($c, "des")===false; });
            $ciphers = array_filter($ciphers, function ($c) { return stripos($c, "rc2")===false; });
            $ciphers = array_filter($ciphers, function ($c) { return stripos($c, "rc4")===false; });
            $ciphers = array_filter($ciphers, function ($c) { return stripos($c, "md5")===false; });
        }

        return $ciphers;
    }
    public static function getAlgorithm($method)
    {
        $lowerName = strtolower($method);

        static $_ = null;

        if($_===null) {
            $_ = array();
        }

        if(!isset($_[$lowerName])) {
            $_[$lowerName] = new Crypt($method);
        }

        return $_[$lowerName];
    }


    private $method;
    private $ivLength;
    private function __construct($method)
    {
        $this->method = $method;
        if(!in_array($this->method, self::getAlgorithms())) {
            throw new CipherAlgorithmNotFoundException($this->method);
        }

        $this->ivLength = openssl_cipher_iv_length($this->method);
        if($this->ivLength===false) {
            throw new IVAlgorithmException($this->method);
        }
    }

    private function getIV()
    {
        return openssl_random_pseudo_bytes($this->ivLength, true);
    }

    public function encrypt($password, $data)
    {
        $iv = $this->getIV();
        return $iv . openssl_encrypt($data, $this->method, $password, 0, $iv);
    }

    public function decrypt($password, $data)
    {
        return openssl_decrypt(substr($data, $this->ivLength), $this->method, $password, 0, substr($data, 0, $this->ivLength));
    }
}
