<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\InvalidPartnerException;
use Bap14\AS2Secure\Message\HeaderCollection;
use Bap14\AS2Secure\Message\MessageAbstract;

/**
 * Class Message
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Message extends MessageAbstract
{
    /** @var  HeaderCollection */
    protected $headers;
    /** @var bool|string */
    protected $micChecksum = false;

    /**
     * Message constructor.
     *
     * @param null $data
     * @param array $params
     */
    public function __construct($data=null, $params=[]) {
        parent::__construct($data, $params);

        if ($data instanceof Request) {
            $this->path = $data->getPath();
        }
        else if ($data instanceof \Horde_Mime_Part) {
            $this->path = $this->adapter->getTempFilename();
            file_put_contents($this->path, $data->toString(['headers' => true]));
        }
        else if ($data) {
            if (!array_key_exists('is_file', $params) || $params['is_file']) {
                $this->addFile($data);
            }
            else {
                $this->addFile($data, null, null, false);
            }
        }

        if (array_key_exists('mic', $params)) {
            $this->micChecksum = $params['mic'];
        }
    }

    /**
     * Add file to message
     *
     * @param string $data
     * @param null $mimeType
     * @param null $filename
     * @param bool $isFile
     * @param string $encoding
     * @return $this
     */
    public function addFile($data, $mimeType=null, $filename=null, $isFile = true, $encoding='base64') {
        if (!$isFile) {
            $file = $this->adapter->getTempFilename();
            file_put_contents($file, $data);
            $data = $file;
        }
        else {
            if (!$filename) {
                $filename = basename($data);
            }
        }

        if (!$mimeType) {
            $mimeType = $this->adapter->detectMimeType($data);
        }

        $this->files[] = [
            'path'     => realpath($data),
            'mimetype' => $mimeType,
            'filename' => $filename,
            'encoding' => $encoding
        ];

        return $this;
    }

    /**
     * Encoding an outgoing message
     *
     * @return $this
     * @throws InvalidPartnerException
     * @throws \Exception
     */
    public function encode() {
        if (!($this->getSendingPartner() instanceof Partner)) {
            throw new InvalidPartnerException('Sending partner must be instanceof Bap14\AS2Secure\Partner');
        }

        if (!($this->getReceivingPartner() instanceof Partner)) {
            throw new InvalidPartnerException('Receiving partner must be instanceof Bap14\AS2Secure\Partner');
        }

        $this->micChecksum = false;
        $this->setMessageId($this->generateMessageId(self::TYPE_SENDING));

        try {
            $mimePart = new \Horde_Mime_Part('multipart/mixed');
            foreach ($this->getFiles() as $file) {
                $part = new \Horde_Mime_Part($file['mimetype']);
                $part->setContents(file_get_contents($file['path']));
                $part->setName($file['filename']);
                if ($file['encoding']) {
                    $part->setTransferEncoding($file['encoding']);
                }

                $mimePart[] = $part;
            }

            $file = $this->adapter->getTempFilename();
            file_put_contents($file, $mimePart->toString());
        }
        catch (\Exception $e) {
            $this->logger->log(Logger::LEVEL_ERROR, $e->getmessage(), $this->getMessageId());
            throw $e;
        }

        if ($this->getReceivingPartner()->getSecSignatureAlgorithm() != Partner::SIGN_NONE) {
            try {
                $file = $this->adapter->sign(
                    $file,
                    $this->getReceivingPartner()->getSendCompress(),
                    $this->getReceivingPartner()->getSendEncoding()
                );
                $this->isSigned = true;
                $this->micChecksum = $this->adapter->getMicChecksum($file);
            }
            catch (\Exception $e) {
                $this->logger->log(Logger::LEVEL_ERROR, $e->getMessage(), $this->getMessageId());
                throw $e;
            }
        }

        if ($this->getReceivingPartner()->getSecEncryptAlgorithm() != Partner::CRYPT_NONE) {
            try {
                $file = $this->encrypt($file);
                $this->isEncrypted = true;
            }
            catch (\Exception $e) {
                $this->logger->log(Logger::LEVEL_ERROR, $e->getMessage(), $this->getMessageId());
                throw $e;
            }
        }

        $this->path = $file;
        $headers = [
            'AS2-From'                    => $this->getSendingPartner()->getId(true),
            'AS2-To'                      => $this->getReceivingPartner()->getId(true),
            'AS2-Version'                 => '1.0',
            'From'                        => $this->getSendingPartner()->getEmail(),
            'Subject'                     => $this->getSendingPartner()->getSendSubject(),
            'Message-ID'                  => $this->getMessageId(),
            'Mime-Version'                => '1.0',
            'Disposition-Notification-To' => $this->getSendingPartner()->getSendUrl(),
            'Recipient-Address'           => $this->getReceivingPartner()->getSendUrl(),
            'User-Agent'                  => Adapter::getSoftwareName()
        ];

        if ($this->getReceivingPartner()->getMdnSigned()) {
            $headers['Disposition-Notification-Options'] = 'signed-receipt-protocol=optional, pkcs7-signature; ';
            $headers['Disposition-Notification-Options'] .= 'signed-receipt-micalg=optional, sha1';
        }

        if ($this->getReceivingPartner()->getMdnRequest()) {
            $headers['Receipt-Delivery-Option'] = $this->getSendingPartner()->getSendUrl();
        }

        $this->headers = new HeaderCollection();
        $this->headers->addHeaders($headers);

        $content = file_get_contents($this->path);
        $this->headers->addHeadersFromMessage($content);

        $mimePart = \Horde_Mime_Part::parseMessage($content);
        file_put_contents($this->path, $mimePart->getContents());

        return $this;
    }

    public function encrypt() {
        // TODO: Implement this
    }

    /**
     * Decode message
     *
     * @return $this
     */
    public function decode() {
        $this->files = $this->adapter->extract($this->getPath());

        return $this;
    }

    /**
     * Generate an MDN for a received message
     *
     * @param Exception|null $exception
     * @return MDN
     */
    public function generateMDN($exception=null) {
        $mdn = new MDN($this);

        $messageId = $this->getHeaders()->getHeader('message-id');
        $partner   = $this->getSendingPartner()->getId(true);
        $mic       = $this->getMicChecksum();

        $mdn->setAttribute('Original-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Final-Recipient', 'rfc822; ' . $partner)
            ->setAttribute('Original-Message-ID', $messageId);

        if ($mic) {
            $mdn->setAttribute('Received-Content-MIC', $mic);
        }

        if ($exception === null) {
            $mdn->setMessage('Successfully received AS2 message ' . $messageId);
            $mdn->setAttribute('Disposition-Type', 'processed');
        }
        else {
            $mdn->setMessage($exception->getMessage());
            $mdn->setAttribute('Disposition-Type', 'failure')
                ->setAttribute('Disposition-Modifier', $exception->getMessage());
        }

        return $mdn;
    }

    /**
     * Get the MIC Checksum
     *
     * @return bool|mixed|string
     */
    public function getMicChecksum() {
        return $this->micChecksum;
    }

    /**
     * Get the receiving partner URL
     *
     * @return string
     */
    public function getUrl() {
        return $this->getReceivingPartner()->getSendUrl();
    }
}