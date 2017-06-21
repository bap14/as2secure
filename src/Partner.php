<?php
/**
 * Copyright 2017 Mars Symbioscience
 *
 * @author   Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\InvalidEncodingException;
use Bap14\AS2Secure\Exception\InvalidEncryptionAlgorithmException;
use Bap14\AS2Secure\Exception\InvalidMdnRequestTypeException;
use Bap14\AS2Secure\Exception\Pkcs12BundleException;
use Bap14\AS2Secure\Exception\InvalidSignatureAlgorithmException;
use Bap14\AS2Secure\Exception\InvalidX509CertificateException;

/**
 * Class Partner
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Partner
{
    const ACKNOWLEDGE_ASYNC = 'async';
    const ACKNOWLEDGE_SYNC  = 'sync';

    const CRYPT_NONE    = 'none';
    const CRYPT_AES_128 = 'aes128';
    const CRYPT_AES_192 = 'aes192';
    const CRYPT_AES_256 = 'aes256';
    const CRYPT_DES     = 'des';
    const CRYPT_3DES    = 'des3';
    const CRYPT_RC2_40  = 'rc2-40';
    const CRYPT_RC2_64  = 'rc2-64';
    const CRYPT_RC2_128 = 'rc2-128';
    const CRYPT_RC4_40  = 'rc4-40';
    const CRYPT_RC4_64  = 'rc4-64';
    const CRYPT_RC4_128 = 'rc4-128';

    const ENCODING_BINARY = 'binary';
    const ENCODING_BASE64 = 'base64';

    const SIGN_NONE   = 'none';
    const SIGN_MD5    = 'md5';
    const SIGN_SHA1   = 'sha1';
    // TODO: Verify implemntation of sha256 and up
    const SIGN_SHA256 = 'sha256';
    const SIGN_SHA384 = 'sha384';
    const SIGN_SHA512 = 'sha512';

    /** @var  Adapter */
    protected $adapter;
    /** @var  string */
    protected $comment;
    /** @var  string */
    protected $email;
    /** @var  string */
    protected $id;
    /** @var  boolean */
    protected $isLocal;
    /** @var  Authentication */
    protected $mdnAuthentication;
    /** @var  string */
    protected $mdnRequest;
    /** @var  boolean */
    protected $mdnSigned;
    /** @var  string */
    protected $mdnSubject;
    /** @var  string */
    protected $mdnUrl;
    /** @var  string */
    protected $secCertificate;
    /** @var  string */
    protected $secEncryptionAlgorithm;
    /** @var  string */
    protected $secPkcs12;
    /** @var  array */
    protected $secPkcs12Contents;
    /** @var  string */
    protected $secPkcs12Password;
    /** @var  string */
    protected $secSignatureAlgorithm;
    /** @var  Authentication */
    protected $sendAuthentication;
    /** @var  boolean */
    protected $sendCompress;
    /** @var  string */
    protected $sendContentType;
    /** @var  string */
    protected $sendEncoding;
    /** @var  string */
    protected $sendSubject;
    /** @var  string */
    protected $sendUrl;

    /**
     * Partner constructor.
     *
     * @param array $data
     */
    public function __construct(array $data=[]) {
        $baseConfig = [
            'comment'  => '',
            'email'    => '',
            'id'       => '',
            'is_local' => false,
            'name'     => '',
            'mdn_authentication' => new Authentication(),
            'mdn_request' => self::ACKNOWLEDGE_SYNC,
            'mdn_signed' => true,
            'mdn_subject' => 'AS2 MDN Subject',
            'mdn_url' => '',
            'sec_certificate' => '',
            'sec_encryption_algorithm' => self::CRYPT_3DES,
            'sec_pkcs12' => '',
            'sec_pkcs12_password' => '',
            'sec_signature_algorithm' => self::SIGN_SHA1,
            'send_authentication' => new Authentication(),
            'send_compress' => false,
            'send_content_type' => 'application/EDI-Consent',
            'send_encoding' => self::ENCODING_BASE64,
            'send_subject' => 'AS2 Message Subject',
            'send_url' => ''
        ];

        $data = array_merge($baseConfig, $data);

        foreach ($data as $key => $value) {
            $methodName = 'set' . str_replace(
                    ' ',
                    '',
                    ucwords(str_replace('_', ' ', $key))
                );

            $this->$methodName($value);
        }
    }

    /**
     * Get list of available acknowledgement types
     *
     * @return array
     */
    public function getAvailableAcknowledgementTypes() {
        return [
            'ASYNC' => self::ACKNOWLEDGE_ASYNC,
            'SYNC'  => self::ACKNOWLEDGE_SYNC
        ];
    }

    /**
     * Get list of available message encoding methods
     *
     * @return array
     */
    public function getAvailableEncodingMethods() {
        return [
            'BASE64' => self::ENCODING_BASE64,
            'BINARY' => self::ENCODING_BINARY
        ];
    }

    /**
     * Get list available encryption methods
     *
     * @return array
     */
    public function getAvailableEncryptionAlgorithms() {
        return [
            'NONE'    => self::CRYPT_NONE,
            'AES_128' => self::CRYPT_AES_128,
            'AES_192' => self::CRYPT_AES_192,
            'AES_256' => self::CRYPT_AES_256,
            'DES'     => self::CRYPT_DES,
            '3DES'    => self::CRYPT_3DES,
            'RC2_40'  => self::CRYPT_RC2_40,
            'RC2_64'  => self::CRYPT_RC2_64,
            'RC2_128' => self::CRYPT_RC2_128,
            'RC4_40'  => self::CRYPT_RC4_40,
            'RC4_64'  => self::CRYPT_RC4_64,
            'RC4_128' => self::CRYPT_RC4_128
        ];
    }

    /**
     * Get list of available signature algorithms
     *
     * @return array
     */
    public function getAvailableSignatureAlgorithms() {
        return [
            'NONE'    => self::SIGN_NONE,
            'MD5'     => self::SIGN_MD5,
            'SHA-1'   => self::SIGN_SHA1,
            'SHA-256' => self::SIGN_SHA256,
            'SHA-384' => self::SIGN_SHA384,
            'SHA-512' => self::SIGN_SHA512
        ];
    }

    /**
     * Get CA Certificate chain from PKCS12 bundle
     *
     * @return bool|string
     */
    public function getCA() {
        return $this->_getDataFromPkcs12('extracerts');
    }

    /**
     * Get comment
     *
     * @return string
     */
    public function getComment() {
        return $this->comment;
    }

    /**
     * Get email address
     *
     * @return string
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * Get partner ID
     *
     * @return string
     */
    public function getId() {
        return $this->id;
    }

    /**
     * Get is partner local to this server
     *
     * @return bool
     */
    public function getIsLocal() {
        return $this->isLocal;
    }

    /**
     * Get authentication object for MDN messages
     *
     * @return Authentication
     */
    public function getMdnAuthentication() {
        return $this->mdnAuthentication;
    }

    /**
     * Get MDN request type
     *
     * @return string Will be one of self::ACKNOWLEDGE_SYNC or self::ACKNOWLEDGE_ASYNC
     */
    public function getMdnRequest() {
        return $this->mdnRequest;
    }

    /**
     * Get whether the MDN is to be signed.
     *
     * @return bool
     */
    public function getMdnSigned() {
        return $this->mdnSigned;
    }

    /**
     * Get MDN subject
     *
     * @return string
     */
    public function getMdnSubject() {
        return $this->mdnSubject;
    }

    /**
     * Get endpoint to send MDN to
     *
     * @return string
     */
    public function getMdnUrl() {
        return $this->mdnUrl;
    }

    /**
     * Retrieve private key from PKCS12 bundle
     *
     * @return bool|string
     */
    public function getPrivateKey() {
        return $this->_getDataFromPkcs12('pkey');
    }

    /**
     * Get the private key file path
     *
     * @return string
     */
    public function getPrivateKeyFile() {
        return $this->_writeFile($this->getId() . '.key', $this->getPrivateKey());
    }

    /**
     * Get public key from PKCS12 bundle
     *
     * @return bool|string
     */
    public function getPublicKey() {
        return $this->_getDataFromPkcs12('cert');
    }

    /**
     * Get the public key file path
     *
     * @return string
     */
    public function getPublicKeyFile() {
        return $this->_writeFile($this->getId() . '.pub', $this->getPublicKey());
    }

    /**
     * Get security certificate (Base64 encoded)
     *
     * @return string
     */
    public function getSecCertificate() {
        return $this->secCertificate;
    }

    /**
     * Get the certificate file path
     *
     * @return string
     */
    public function getSecCertificateFile() {
        return $this->_writeFile($this->getId() . '.cer', $this->getSecCertificate());
    }

    /**
     * Get security encryption algorithm
     *
     * @return string One of the CRYPT_* constants
     */
    public function getSecEncryptAlgorithm() {
        return $this->secEncryptionAlgorithm;
    }

    /**
     * Get secure PKCS12 bundle
     *
     * @return string
     */
    public function getSecPkcs12() {
        return $this->secPkcs12;
    }

    /**
     * Get the PKCS12 bundle file path
     *
     * @return string
     */
    public function getSecPkcs12File() {
        return $this->_writeFile($this->getId() . '.p12', $this->getSecPkcs12());
    }

    /**
     * Get PKCS12 bundle password (if any)
     *
     * @return string
     */
    public function getSecPkcs12Password() {
        return $this->secPkcs12Password;
    }

    /**
     * Get security signature algorithm
     *
     * @return string
     */
    public function getSecSignatureAlgorithm() {
        return $this->secSignatureAlgorithm;
    }

    /**
     * Get authentication object for message destination
     *
     * @return Authentication
     */
    public function getSendAuthentication() {
        return $this->sendAuthentication;
    }

    /**
     * Get flag to send data compressed or not
     *
     * @return bool
     */
    public function getSendCompress() {
        return $this->sendCompress;
    }

    /**
     * Get the content-type of the message
     *
     * @return string
     */
    public function getSendContentType() {
        return $this->sendContentType;
    }

    /**
     * Get the encoding of the message
     *
     * @return string
     */
    public function getSendEncoding() {
        return $this->sendEncoding;
    }

    /**
     * Get the message subject
     *
     * @return string
     */
    public function getSendSubject() {
        return $this->sendSubject;
    }

    /**
     * Get the endpoint to send the message to
     *
     * @return string
     */
    public function getSendUrl() {
        return $this->sendUrl;
    }

    /**
     * Set the adapter to use for file activities
     *
     * @param Adapter $adapter
     * @return $this
     */
    public function setAdapter(Adapter $adapter) {
        $this->adapter = $adapter;
        return $this;
    }

    /**
     * Set message comment
     *
     * @param string $comment
     * @return $this
     */
    public function setComment($comment='') {
        $this->comment = $comment;
        return $this;
    }

    /**
     * Set email address
     *
     * @param $email
     * @return $this
     */
    public function setEmail($email) {
        $this->email = $email;
        return $this;
    }

    /**
     * Set partner ID
     *
     * @param $id
     * @return $this
     */
    public function setId($id) {
        $this->id = $id;
        return $this;
    }

    /**
     * Set whether this partner is local to this server
     *
     * @param $isLocal
     * @return $this
     */
    public function setIsLocal($isLocal) {
        $this->isLocal = $isLocal;
        return $this;
    }

    /**
     * Set MDN authentication object
     *
     * @param Authentication $auth
     * @return $this
     */
    public function setMdnAuthentication(Authentication $auth) {
        $this->mdnAuthentication = $auth;
        return $this;
    }

    /**
     * Set MDN request type
     *
     * @param $request
     * @return $this
     * @throws InvalidMdnRequestTypeException
     */
    public function setMdnRequest($request) {
        if (!in_array($request, array_values($this->getAvailableAcknowledgementTypes()))) {
            throw new InvalidMdnRequestTypeException('Expected request type to be "sync" or "async"');
        }
        $this->mdnRequest = $request;
        return $this;
    }

    /**
     * Set whether MDN is to be signed
     *
     * @param $signed
     * @return $this
     */
    public function setMdnSigned($signed) {
        $this->mdnSigned = $signed;
        return $this;
    }

    /**
     * Set subject of MDN
     *
     * @param $subject
     * @return $this
     */
    public function setMdnSubject($subject) {
        $this->mdnSubject = $subject;
        return $this;
    }

    /**
     * Set MDN endpoint URL
     *
     * @param $url
     * @return $this
     */
    public function setMdnUrl($url) {
        $this->mdnUrl = $url;
        return $this;
    }

    /**
     * Set security certificate (Base64 encoded)
     *
     * @param string $certificate Base64 encoded certificate
     * @return $this
     * @throws InvalidX509CertificateException
     */
    public function setSecCertificate($certificate) {
        if (is_file($certificate)) {
            $this->secCertificate = file_get_contents($certificate);
        } else {
            // Check to see it's a valid x509 cert
            $certInfo = openssl_x509_parse($certificate);
            if (!is_array($certInfo)) {
                throw new InvalidX509CertificateException(
                    'Security certificate was not able to be parsed as x509 certificate'
                );
            }
            unset($certInfo);
            $this->secCertificate = $certificate;
        }
        return $this;
    }

    /**
     * Set security encryption algorithm
     *
     * @param $algorithm
     * @return $this
     * @throws InvalidEncryptionAlgorithmException
     */
    public function setSecEncryptAlgorithm($algorithm) {
        if (!in_array($algorithm, array_values($this->getAvailableEncryptionAlgorithms()))) {
            throw new InvalidEncryptionAlgorithmException(
                sprintf('Unknown encryption algorithm "%s".', $algorithm)
            );
        }
        $this->secEncryptionAlgorithm = $algorithm;
        return $this;
    }

    /**
     * Set the PKCS12 bundle.  The PKCS12 password should be set, if needed, prior to calling this method.
     *
     * @param $pkcs12
     * @return $this
     * @throws Pkcs12BundleException
     */
    public function setSecPkcs12($pkcs12) {
        if (is_file($pkcs12)) {
            $this->secPkcs12 = file_get_contents($pkcs12);
        } else {
            // Check for valid PKCS12 bundle
            $bundle = [];
            $valid = openssl_pkcs12_read($pkcs12, $bundle, $this->getSecPkcs12Password());
            if (!$valid) {
                throw new Pkcs12BundleException('Unable to verify PKCS12 bundle');
            }
            unset($bundle, $valid);
            $this->secPkcs12 = $pkcs12;
        }
        return $this;
    }

    /**
     * Se the PKCS12 bundle password
     *
     * @param $password
     * @return $this
     */
    public function setSecPkcs12Password($password) {
        $this->secPkcs12Password = $password;
        return $this;
    }

    /**
     * Set the security signature algorithm
     *
     * @param $algorithm
     * @return $this
     * @throws InvalidSignatureAlgorithmException
     */
    public function setSecSignatureAlgorithm($algorithm) {
        if (!in_array($algorithm, array_values($this->getAvailableSignatureAlgorithms()))) {
            throw new InvalidSignatureAlgorithmException(
                sprintf('Unknown signature algorithm "%s".', $algorithm)
            );
        }
        $this->secSignatureAlgorithm = $algorithm;
        return $this;
    }

    /**
     * Set authentication object for message endpoint
     *
     * @param Authentication $auth
     * @return $this
     */
    public function setSendAuthentication(Authentication $auth) {
        $this->sendAuthentication = $auth;
        return $this;
    }

    /**
     * Set whether message is compressed or not
     *
     * @param $compress
     * @return $this
     */
    public function setSendCompress($compress) {
        $this->sendCompress = $compress;
        return $this;
    }

    /**
     * Set message content type
     *
     * @param $contentType
     * @return $this
     */
    public function setSendContentType($contentType) {
        $this->sendContentType = $contentType;
        return $this;
    }

    /**
     * Set message encoding
     *
     * @param $encoding
     * @return $this
     * @throws InvalidEncodingException
     */
    public function setSendEncoding($encoding) {
        if (!in_array($encoding, array_values($this->getAvailableEncodingMethods()))) {
            throw new InvalidEncodingException(sprintf('Unsupported encoding "%s"', $encoding));
        }
        $this->sendEncoding = $encoding;
        return $this;
    }

    /**
     * Set message subject
     *
     * @param $subject
     * @return $this
     */
    public function setSendSubject($subject) {
        $this->sendSubject = $subject;
        return $this;
    }

    /**
     * Set message endpoint URL
     *
     * @param $url
     * @return $this
     */
    public function setSendUrl($url) {
        $this->sendUrl = $url;
        return $this;
    }

    /**
     * Extract data from a PKCS12 bundle.  Cache the bundle in-memory for multiple calls.
     *
     * @param $key
     * @return bool|string
     * @throws Pkcs12BundleException
     */
    protected function _getDataFromPkcs12($key) {
        if (!$this->secPkcs12Contents) {
            $this->secPkcs12Contents = [];
            openssl_pkcs12_read($this->getSecPkcs12(), $certs, $this->getSecPkcs12Password());
        }

        if (!array_key_exists($key, $this->secPkcs12Contents)) {
            throw new Pkcs12BundleException(spritnf('Unable to locate "%s" within PKCS12 Bundle', $key));
        }

        $destinationFile = $this->adapter->getTempFilename();
        file_put_contents($this->secPkcs12Contents[$key]);
        $this->adapter->addTempFileForDelete($destinationFile);

        return $destinationFile;
    }

    /**
     * Write a file to the _private directory and return full path to file.  If file exists and the contents are the
     * the same, just return the file path.
     *
     * @param $filename
     * @param $contents
     * @return bool|string
     */
    protected function _writeFile($filename, $contents) {
        $filePath = realpath(dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_private');
        $filePath .= DIRECTORY_SEPARATOR . $filename;

        $writeNewFile = true;
        if (file_exists($filePath)) {
            $pkeyContents = file_get_contents($filePath);
            if ($pkeyContents == $contents) {
                $writeNewFile = false;
            }
        }

        if ($writeNewFile) {
            $fp = fopen($filePath, 'w+b');
            file_put_contents($fp, $contents);
            @fclose($fp);
        }

        return $filePath;
    }
}