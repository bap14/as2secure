<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author   Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure\Message;

/**
 * Class HeaderCollection
 *
 * @package Bap14\AS2Secure\Message
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class HeaderCollection implements \Countable, \ArrayAccess, \Iterator
{
    protected $headers = [];
    protected $normalizedHeaders;
    protected $position = 0;

    public function __toString() {
        return implode("\n", $this->toArray());
    }

    public function addHeader($name, $value) {
        $this->headers[$name] = $value;
        $this->normalizedHeaders = null;
        return $this;
    }

    public function addHeaders(array $headers) {
        foreach ($headers as $key => $value) {
            $this->addHeader($key, $value);
        }
        return $this;
    }

    public function count() {
        return count($this->headers);
    }

    public function current() {
        return $this->headers[$this->key()];
    }

    public function exists($name) {
        return array_key_exists(strtolower($name), $this->getNormalizedHeaders());
    }

    public function getHeader($name) {
        $tmp = array_change_key_case($this->headers, CASE_LOWER);
        if (array_key_exists($name, $tmp)) {
            return $tmp[$name];
        }

        return false;
    }

    public function getNormalizedHeaders() {
        if (!$this->normalizedHeaders) {
            $this->normalizedHeaders = array_change_key_case($this->headers);
        }
        return $this->normalizedHeaders;
    }

    public function key() {
        return array_keys($this->headers)[$this->position];
    }

    public function next() {
        $this->position++;
    }

    public function offsetExists($offset) {
        return array_key_exists($this->headers, $offset);
    }

    public function offsetGet($offset) {
        if ($this->offsetExists($offset)) {
            return $this->headers[$offset];
        }
        return null;
    }

    public function offsetSet($offset, $value) {
        $this->headers[$offset] = $value;
        return $this;
    }

    public function offsetUnset($offset) {
        if ($this->offsetExists($offset)) {
            unset($this->headers[$offset]);
        }
        return $this;
    }

    public function parseContent($content) {
        $returnVal = new HeaderCollection();

        $delimiter = strpos($content, "\n\n");
        if ($delimiter !== false) {
            $content = substr($content, 0, $delimiter);
        }
        $content = rtrim($content, "\n");

        $headers = [];
        preg_match_all('/(.*?):\s*(.*?\n(\s.*?\n)*)/', $content, $headers);
        if ($headers) {
            foreach ($headers[2] as $key => $value) {
                $headers[2][$key] = trim(str_replace(["\r", "\n"], ' ', $value));
            }

            if (count($headers[1]) && count($headers[1]) == count($headers[2])) {
                $returnVal->addHeaders(array_combine($headers[1], $headers[2]));
            }
        }

        return $returnVal;
    }

    public function parseHttpRequest() {
        $returnVal = new HeaderCollection();

        if (!function_exists('apache_request_headers')) {
            $headers = [
                'Content-Type'   => $_SERVER['CONTENT_TYPE'],
                'Content-Length' => $_SERVER['CONTENT_LENGTH']
            ];
            foreach ($_SERVER as $key => $value) {
                if (strpos($key, 'HTTP_') === 0) {
                    $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                    $headers[$key] = $value;
                }
            }
            $returnVal->addheaders($headers);
        } else {
            $returnVal->addHeaders(apache_request_headers());
        }

        return $returnVal;
    }

    public function removeHeader($name) {
        if (array_key_exists($name, $this->headers)) {
            unset($this->headers[$name]);
            $this->normalizedHeaders = null;
        }
        return $this;
    }

    public function rewind() {
        $this->position = 0;
    }

    public function toArray() {
        $returnVal = [];
        foreach ($this->headers as $key => $value) {
            $returnVal[] = $key . ': ' . $value;
        }
        return $returnVal;
    }

    public function valid() {
        return ($this->position >= 0 && $this->position < count($this->headers));
    }
}