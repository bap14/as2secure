<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author   Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure\Message;

use Bap14\AS2Secure\Exception\InvalidPartnerException;
use Bap14\AS2Secure\Adapter;
use Bap14\AS2Secure\Authentication;
use Bap14\AS2Secure\Logger;
use Bap14\AS2Secure\Partner;

/**
 * Class MessageAbstract
 *
 * @package Bap14\AS2Secure\Message
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
abstract class MessageAbstract
{
    const TYPE_RECEIVING = 'receiving';
    const TYPE_SENDING = 'sending';

    /** @var  Adapter */
    protected $adapter;

    /** @var  Authentication */
    protected $authentication;

    /** @var  string */
    protected $filename;

    /** @var  array */
    protected $files = [];

    /** @var HeaderCollection */
    protected $headerCollection;

    /** @var  boolean */
    protected $isEncrypted;

    /** @var  boolean */
    protected $isSigned;

    /** @var  Logger */
    protected $logger;

    /** @var  string */
    protected $messageId;

    /** @var  string */
    protected $mimetype;

    /** @var  array */
    protected $path = [];

    /** @var  Partner */
    protected $receivingPartner;

    /** @var  Partner */
    protected $sendingPartner;

    /**
     * Decode received message with configured partner details.
     *
     * @return $this
     */
    abstract function decode();

    /**
     * Encode outgoing message with configured partner details.
     *
     * @return $this
     */
    abstract function encode();

    /**
     * Retrieve message destination URL.
     *
     * @return string
     */
    abstract function getUrl();

    /**
     * MessageAbstract constructor.
     *
     * @param $data
     * @param array $params
     */
    public function __construct($data=null, $params=[]) {
        $this->adapter          = new Adapter();
        $this->authentication   = new Authentication();
        $this->headerCollection = new HeaderCollection();
        $this->logger           = Logger::getInstance();

        if (is_array($data)) {
            $this->setPath($data);
        }
        else if ($data) {
            if (array_key_exists('is_file', $params) && $params['is_file'] === false) {
                $file = $this->adapter->getTempFilename();
                file_put_contents($file, $data);
                $this->setPath($file);

                if (array_key_exists('filename', $params)) {
                    $this->setFilename($params['filename']);
                }
            }
            else {
                $this->setPath($data);
                $this->setFilename(
                    array_key_exists('filename', $params) ? $params['filename'] : basename($this->getPath())
                );
            }

            $this->setMimetype(
                array_key_exists('mimetype', $params) ?
                        $params['mimetype'] : $this->adapter->detectMimeType($this->getFilename())
            );
        }
    }

    /**
     * Add file to message
     *
     * @param string $file
     * @return array
     */
    public function addFile($file) {
        return $this->files[] = realpath($file);
    }

    /**
     * Get the authentication configuration
     *
     * @return Authentication
     */
    public function getAuthentication() {
        return $this->authentication;
    }

    /**
     * @return bool|string
     */
    public function getContents() {
        return file_get_contents($this->path);
    }

    /**
     * Get message filename.
     *
     * @return string
     */
    public function getFilename() {
        return $this->filename;
    }

    /**
     * Get all files attached to this message.
     *
     * @return array
     */
    public function getFiles() {
        return $this->files;
    }

    /**
     * Get HeaderCollection object to manage headers
     *
     * @return HeaderCollection
     */
    public function getHeaders() {
        return $this->headerCollection;
    }

    /**
     * Get whether or not this message is encrypted.
     *
     * @return bool
     */
    public function getIsEncrypted() {
        return $this->isEncrypted;
    }

    /**
     * Get whether or not this message is signed.
     *
     * @return bool
     */
    public function getIsSigned() {
        return $this->isSigned;
    }

    /**
     * Get the unique message ID
     *
     * @return string
     */
    public function getMessageId() {
        return $this->messageId;
    }

    /**
     * Get mimetype of message
     *
     * @return string
     */
    public function getMimetype() {
        return $this->mimetype;
    }

    /**
     * Get path of message.
     *
     * @return array
     */
    public function getPath() {
        return $this->path;
    }

    /**
     * Get the receiving partner identity
     *
     * @return Partner
     * @throws InvalidPartnerException
     */
    public function getReceivingPartner() {
        if (!($this->receivingPartner instanceof Partner)) {
            throw new InvalidPartnerException('Receiving partner has not been set, or was not configured properly.');
        }

        return $this->receivingPartner;
    }

    /**
     * Get the sending partner identity
     *
     * @return Partner
     * @throws InvalidPartnerException
     */
    public function getSendingPartner() {
        if (!($this->sendingPartner instanceof Partner)) {
            throw new InvalidPartnerException('Sending partner has not been set, or was not configured properly.');
        }
        return $this->sendingPartner;
    }

    /**
     * Set message filename.
     *
     * @param string $filename
     * @return string
     */
    public function setFilename($filename) {
        return $this->filename = $filename;
    }

    /**
     * Set the unique message ID
     *
     * @param $messageId
     * @return $this
     */
    public function setMessageId($messageId) {
        $this->messageId = $messageId;
        return $this;
    }

    /**
     * Set mimetype of message
     *
     * @param $mimetype
     * @return $this
     */
    public function setMimetype($mimetype) {
        $this->mimetype = $mimetype;
        return $this;
    }

    /**
     * Set path of message.
     *
     * @param array $path
     * @return $this
     */
    public function setPath(array $path) {
        $this->path = $path;
        return $this;
    }

    /**
     * Set the receiving partner identity
     *
     * @param Partner|array $partner
     *
     * @return $this
     */
    public function setReceivingPartner($partner) {
        if (!($partner instanceof Partner)) {
            $this->receivingPartner = new Partner();
            $this->copyPartnerParamters($partner, $this->receivingPartner);
        } else {
            $this->receivingPartner = $partner;
        }

        return $this;
    }

    /**
     * Set the sending partner identity
     *
     * @param Partner|array $partner
     *
     * @return $this
     */
    public function setSendingPartner($partner) {
        if (!($partner instanceof Partner)) {
            $this->sendingPartner = new Partner();
            $this->copyPartnerParamters($partner, $this->sendingPartner);
        } else {
            $this->sendingPartner = $partner;
        }

        return $this;
    }

    /**
     * Copy partner data from an array to a Partner object.
     *
     * @param $source
     * @param $destination
     */
    protected function copyPartnerParamters(array $source, Partner $destination)
    {
        // TODO: Assign data from $source to $destination
    }

    /**
     * Generate a unique message ID for a partner.
     *
     * @param string $type Either self::TYPE_SENDING or self::TYPE_RECEIVING
     *
     * @return string
     */
    final protected function generateMessageId($type=self::TYPE_SENDING) {
        try {
            switch ($type) {
                case self::TYPE_RECEIVING:
                    $partner = $this->getReceivingPartner()->getId();
                    break;

                case self::TYPE_SENDING:
                    $partner = $this->getSendingPartner()->getId();
                    break;

                default:
                    throw new InvalidPartnerException('Invalid partner to generate message ID for');
            }
        }
        catch (\Exception $e) {
            $partner = 'unknown';
        }

        return sprintf(
            '<%s@%s_%s_%s>',
            uniqid('', true),
            microtime(),
            str_replace(' ', '', strtolower($partner)),
            php_uname('n')
        );
    }
}