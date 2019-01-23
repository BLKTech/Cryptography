<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace BLKTech\Cryptography;

/**
 * Description of Crypt
 *
 * @author instalacion
 */
class Crypt {
    
    
    public static function getAlgorithms()
    {
        static $ciphers = null;
        
        if($ciphers===null)
        {
            $ciphers = openssl_get_cipher_methods();        

            //ECB mode should be avoided
            $ciphers = array_filter( $ciphers, function($n) { return stripos($n,"ecb")===FALSE; } );

            //At least as early as Aug 2016, Openssl declared the following weak: RC2, RC4, DES, 3DES, MD5 based
            $ciphers = array_filter( $ciphers, function($c) { return stripos($c,"des")===FALSE; } );
            $ciphers = array_filter( $ciphers, function($c) { return stripos($c,"rc2")===FALSE; } );
            $ciphers = array_filter( $ciphers, function($c) { return stripos($c,"rc4")===FALSE; } );
            $ciphers = array_filter( $ciphers, function($c) { return stripos($c,"md5")===FALSE; } );
        }
        
        return $ciphers;
    }    
    public static function getAlgorithm($method)
    {
        $lowerName = strtolower($method);
        
        static $_ = null;
        
        if($_===null)
            $_ = array();
        
        if(!isset($_[$lowerName]))
            $_[$lowerName] = new Crypt($method);
                        
        return $_[$lowerName];
    }    

    
    private $method;   
    private $ivLength;
    private function __construct($method)
    {
        $this->method = $method;        
        if(!in_array($this->method, self::getAlgorithms()))
            throw new CipherAlgorithmNotFoundException($this->method);            
        
        $this->ivLength = openssl_cipher_iv_length($this->method);
        if($this->ivLength===FALSE)
            throw new IVAlgorithmException($this->method);            
    }
    
    private function getIV()
    {
        return openssl_random_pseudo_bytes($this->ivLength,true);
    }
    
    public function encrypt($password,$data)
    {
        $iv = $this->getIV();
        return $iv . openssl_encrypt($data, $this->method, $password, 0, $iv);
    }
    
    public function decrypt($password,$data)
    {
        return openssl_decrypt(substr($data, $this->ivLength), $this->method, $password, 0, substr($data, 0, $this->ivLength));        
    }    
}
