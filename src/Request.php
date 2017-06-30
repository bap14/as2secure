<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\MessageDecryptionException;
use Bap14\AS2Secure\Exception\MethodNotAvailableException;
use Bap14\AS2Secure\Exception\UnencryptedMessageException;
use Bap14\AS2Secure\Exception\UnsignedMdnException;
use Bap14\AS2Secure\Exception\UnsignedMessageException;
use Bap14\AS2Secure\Message\MessageAbstract;

/**
 * Class Request
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Request extends MessageAbstract
{
    /**
     * Not Implemented
     *
     * @throws MethodNotAvailableException
     */
    public function decode() {
        throw new MethodNotAvailableException('Method "decode" is not available on a Request message.');
    }

    /**
     * Decrypt received message
     *
     * @return bool|string
     * @throws \Exception
     */
    public function decrypt() {
        $returnVal = false;
        $mimeType = $this->getHeaders()->getHeader('Content-Type');
        $position = strpos($mimeType, ';');
        if ($position !== false) {
            $mimeType = trim(substr($mimeType, 0, $position));
        }

        if ($mimeType == 'application/pkcs7-mime' || $mimeType == 'application/x-pkcs7-mime') {
            try {
                $content = $this->getHeaders()->__toString() . "\n\n";
                $content .= file_get_contents($this->getPath());



                $input = $this->adapter->getTempFilename();
                $mimePart = \Horde_Mime_Part::parseMessage($content);
                file_put_contents($input, $mimePart->toString());

                $returnVal = $this->adapter->decrypt($input);
                return $returnVal;
            }
            catch (\Exception $e) {
                throw $e;
            }
        }

        return $returnVal;
    }

    /**
     * Not implemented
     *
     * @throws MethodNotAvailableException
     */
    public function encode() {
        throw new MethodNotAvailableException('Method "encode" is not available on a Request message.');
    }

    /**
     * Get aon object from a received message
     *
     * @return Mdn|Message
     */
    public function getObject() {
        // TODO: Is the tempfile necessary?
        $content = $this->getHeaders()->__toString() . "\n\n";
        $content .= file_get_contents($this->getPath());
        $input = $this->adapter->getTempFilename();

        file_put_contents($input, $content);

        $params = [
            'include_bodies' => false,
            'decode_headers' => true,
            'decode_bodies'  => false,
            'input'          => false
        ];
        $decoder = new \Mail_mimeDecode(file_get_contents($input));
        $structure = $decoder->decode($params);
        $mimeType = strtolower($structure->ctype_primary . '/' . $structure->ctype_secondary);

        $encrypted = $this->decryptMessageHeaders($input, $content, $mimeType, $structure);
        $mic = false;
        $signed = $this->verifySignature($input, $mimeType, $structure, $mic);

        $this->checkMessageConstruction($mimeType, $signed, $encrypted);

        $message = file_get_contents($input);
        $mimePart = \Horde_Mime_Part::parseMessage($message);

        $params = [
            'is_file'           => false,
            'mic'               => $mic,
            'receiving_partner' => $this->getReceivingPartner(),
            'sending_partner'   => $this->getSendingPartner()
        ];

        switch (strtolower($mimeType)) {
            case 'multipart/report':
                $object = new Mdn($mimePart, $params);
                break;

            default:
                $object = new Message($mimePart, $params);
                break;
        }

        $object->setHeaders($this->getHeaders());
        return $object;
    }

    /**
     * Not Implemented
     *
     * @throws MethodNotAvailableException
     */
    public function getUrl() {
        throw new MethodNotAvailableException('Method "getUrl" is not available on a Request message.');
    }

    /**
     * Check a message or MDN is signed and encrypted according to partner configuration
     *
     * @param string $mimeType
     * @param boolean $signed
     * @param boolean $encrypted
     * @throws UnencryptedMessageException
     * @throws UnsignedMdnException
     * @throws UnsignedMessageException
     */
    protected function checkMessageConstruction($mimeType, $signed, $encrypted) {
        if (strtolower($mimeType) === 'multipart/report') {
            if (
                $this->getSendingPartner()->getSecSignatureAlgorithm() != Partner::SIGN_NONE &&
                $this->getSendingPartner()->getMdnSigned() &&
                !$signed
            ) {
                throw new UnsignedMdnException('MDN is not signed but partner is configured for signed MDNs');
            }
        } else {
            if (
                $this->getSendingPartner()->getSecEncryptAlgorithm() != Partner::CRYPT_NONE &&
                !$encrypted
            ) {
                throw new UnencryptedMessageException(
                    'Message is not encrypted but partner is configured for encrypted messages'
                );
            }

            if (
                $this->getSendingPartner()->getSecSignatureAlgorithm() != Partner::SIGN_NONE &&
                !$signed
            ) {
                throw new UnsignedMessageException(
                    'Message is not signed but partner is configured for signed messages'
                );
            }
        }
    }

    /**
     * Decrypt message headers
     *
     * @param $inputFilename
     * @param $content
     * @param $mimeType
     * @param $structure
     * @return bool
     * @throws MessageDecryptionException
     */
    protected function decryptMessageHeaders(&$inputFilename, &$content, &$mimeType, &$structure) {
        $returnValue = false;
        if (strtolower($mimeType) === 'application/pkcs7-mime') {
            try {
                $message = \Horde_Mime_Part::parseMessage($content);
                $inputFilename = $this->adapter->getTempFilename();
                file_put_contents($inputFilename, $message->toString(['headers' => true]));

                $this->logger->log(Logger::LEVEL_INFO, 'AS2 Message is encrypted');

                $inputFilename = $this->adapter->decrypt($inputFilename);
                $returnValue = true;

                $this->logger->log(Logger::LEVEL_INFO, 'Data decrypted using ' . $this->getSendingPartner()->getId() . ' key');

                $decoder = new \Mail_mimeDecode(file_get_contents($inputFilename));
                $structure = $decoder->decode([
                    'include_bodies' => false,
                    'decode_headers' => true,
                    'decode_bodies'  => false,
                    'input'          => false
                ]);
                $mimeType = $structure->ctype_primary . '/' . $structure->ctype_secondary;
            }
            catch (\Exception $e) {
                throw new MessageDecryptionException($e->getMessage());
            }
        }

        return $returnValue;
    }

    /**
     * Verify the signature of the message
     *
     * @param $input
     * @param $mimeType
     * @param $structure
     * @param $mic
     * @return bool
     */
    protected function verifySignature(&$input, &$mimeType, &$structure, &$mic) {
        $returnValue = false;

        if (strtolower($mimeType) === 'multipart/signed') {
            try {
                $this->logger->log(Logger::LEVEL_INFO, 'AS2 message is signed');
                $mic = $this->adapter->getMicChecksum($input);
                $input = $this->adapter->verify($input);
                $returnValue = true;

                $this->logger->log(
                    Logger::LEVEL_INFO,
                    sprintf(
                        'The sender used the algorithm %s to sign the message',
                        $structure->ctype_parameters['micalg']
                    )
                );

                $decoder = new \Mail_mimeDecode(file_get_contents($input));
                $structure = $decoder->decode([]);
                $mimeType = $structure->ctype_primary . '/' . $structure->ctype_secondary;

                $this->logger->log(
                    Logger::LEVEL_INFO,
                    sprintf(
                        'Using certificate %s to verify signature',
                        $this->getSendingPartner()->getId()
                    )
                );
            }
            catch (\Exception $e) {
            }
        } else {
            $mic = $this->adapter->calculateMicChecksum($input, 'sha1');
        }

        return $returnValue;
    }
}