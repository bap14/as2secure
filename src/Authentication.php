<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

/**
 * Class Authentication
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Authentication
{
    const METHOD_NONE   = 'none';
    const METHOD_AUTO   = CURLAUTH_ANY;
    const METHOD_BASIC  = CURLAUTH_BASIC;
    const METHOD_DIGEST = CURLAUTH_DIGEST;
    const METHOD_NTLM   = CURLAUTH_NTLM;
    const METHOD_GSS    = CURLAUTH_GSSNEGOTIATE;

    /**
     * @var string
     */
    protected $method = self::METHOD_NONE;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $password;

    /**
     * Get authentication method
     *
     * @return int|string
     */
    public function getMethod() {
        return $this->method;
    }

    /**
     * Get authentication password
     *
     * @return string
     */
    public function getPassword() {
        return $this->password;
    }

    /**
     * get authentication username
     *
     * @return string
     */
    public function getUsername() {
        return $this->username;
    }

    /**
     * Determine if authentication is required or not
     *
     * @return bool TRUE if auth is configured, FALSE otherwise
     */
    public function hasAuthentication() {
        return $this->method !== self::METHOD_NONE;
    }

    /**
     * Set authentication method to use
     *
     * @param $method
     * @return $this
     */
    public function setMethod($method) {
        $this->method = $method;
        return $this;
    }

    /**
     * Set password used for authentication
     *
     * @param $password
     * @return $this
     */
    public function setPassword($password) {
        $this->password = $password;
        return $this;
    }

    /**
     * Set username used for authentication
     *
     * @param $username
     * @return $this
     */
    public function setUsername($username) {
        $this->username = $username;
        return $this;
    }
}