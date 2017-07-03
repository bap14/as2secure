<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\InvalidMessageException;
use Bap14\AS2Secure\Exception\UnsignedMdnException;
use Bap14\AS2Secure\Message\HeaderCollection;
use Bap14\AS2Secure\Message\MessageAbstract;

/**
 * Class MDN
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class MDN extends MessageAbstract
{
    const ACTION_AUTO    = 'automatic-action';
    const ACTION_MANUAL  = 'manual-action';
    const MOD_ERROR      = 'error';
    const MOD_WARN       = 'warning';
    const MODE_AUTO      = 'MDN-sent-automatically';
    const MODE_MANUAL    = 'MDN-sent-manually';
    const TYPE_PROCESSED = 'processed';
    const TYPE_FAILED    = 'failed';

    /** @var HeaderCollection */
    protected $attributes;
    /** @var  Message */
    protected $message;
    /** @var  string */
    protected $url;

    /**
     * MDN constructor.
     * @param null $data
     * @param array $params
     * @throws InvalidMessageException
     * @throws UnsignedMdnException
     */
    public function __construct($data=null, $params=[]) {
        parent::__construct();

        $this->attributes = new HeaderCollection();
        $this->setAttribute('action-mode', self::ACTION_AUTO)
            ->setAttribute('sending-mode', self::MODE_AUTO);

        if ($data instanceof \Exception) {
            $this->setMessage($data->getMessage());
            $this->setAttribute('disposition-type', $data->getLevel())
                ->setAttribute('disposition-modifier', $data->getmessageShort());

            $this->setSendingPartner($params['sending_partner']);
            $this->setReceivingPartner($params['receiving_partner']);
        }
        else if ($data instanceof Request) {
            $this->setSendingPartner($data->getSendingPartner())
                ->setReceivingPartner($data->getReceivingPartner())
                ->setPath($data->getContents())
                ->setFilename(basename($data->getContents()))
                ->setMimetype('multipart/report');

            if ($this->getSendingPartner()->getMdnSigned() && !$data->getIsSigned()) {
                throw new UnsignedMdnException('Unsigned MDN received but partner is expecting signed MDN');
            }
        }
        else if ($data instanceof Message) {
            $this->setSendingPartner($data->getSendingPartner())
                ->setReceivingPartner($data->getReceivingPartner());
        }
        else if ($data instanceof \Horde_Mime_Part) {
            $this->setSendingPartner($params['sending_partner'])
                ->setReceivingPartner($params['receiving_partner'])
                ->setPath($this->adapter->getTempFilename());

            file_put_contents($this->getPath(), $data->toString(true));
        }
        else {
            throw new InvalidMessageException('Unexpected message encountered.  Expected Request, Message or Mime Part');
        }
    }

    /**
     * Convert MDN to string
     *
     * @return string
     */
    public function __toString() {
        return (string) $this->getMessage();
    }

    /**
     * Encode MDN for sending
     *
     * @param Message $message Message for MDN
     * @return $this
     */
    public function encode(Message $message=null) {
        $container = new \Horde_Mime_Part();
        $container->setType('multipart/report');

        $textPart = new \Horde_Mime_Part();
        $textPart->setType('text/plain');
        $textPart->setContents($this->getMessage());
        $textPart->setTransferEncoding(\Horde_Mime_Part::ENCODE_7BIT);

        $container[] = $textPart;

        $lines = new HeaderCollection();
        $lines->addHeader('Reporting-UA', Adapter::getServerSignature());
        if ($this->getSendingPartner()) {
            $lines->addHeader('Original-Recipient', 'rfc822; ' . $this->getSendingPartner()->getId(true));
            $lines->addHeader('Final-Recipient', 'rfc822; ' . $this->getSendingPartner()->getId(true));
        }
        $lines->addHeader('Original-Message-ID', $this->getOriginalMessageId());
        $lines->addHeader(
            'Disposition',
            sprintf(
                '%s/%s; %s',
                $this->getActionMode(),
                $this->getSendingMode(),
                $this->getDispositionType()
            )
        );
        if ($this->getDispositionType() !== self::TYPE_PROCESSED) {
            $lines->addHeader(
                'Disposition',
                $lines->getHeader('Disposition') . ': ' . $this->getDispositionModifier()
            );
        }
        if ($this->getReceivedContentMic()) {
            $lines->addHeader('Received-Content-MIC', $this->getReceivedContentMic());
        }

        $mdn = new \Horde_Mime_Part();
        $mdn->setType('message/disposition-notification');
        $mdn->setContents($lines);
        $mdn->setTransferEncoding(\Horde_Mime_Part::ENCODE_7BIT);

        $this->setMessageId($this->generateMessageId($this->getSendingPartner()));

        $this->headerCollection->addHeaders([
            'AS2-Version'  => '1.0',
            'Message-ID'   => $this->getMessageId(),
            'Mime-Version' => '1.0',
            'Server'       => Adapter::getServerSignature(),
            'User-Agent'   => Adapter::getServerSignature()
        ]);

        $this->headerCollection->addHeaders($container->addMimeHeaders());

        if ($this->getSendingPartner()) {
            $this->headerCollection->addHeaders([
                'AS2-From'                    => $this->getSendingPartner()->getId(true),
                'From'                        => $this->getSendingPartner()->getEmail(),
                'Subject'                     => $this->getSendingPartner()->getMdnSubject(),
                'Disposition-Notification-To' => $this->getSendingPartner()->getSendUrl()
            ]);
        }

        if ($this->getReceivingPartner()) {
            $this->headerCollection->addHeaders([
                'AS2-To'            => $this->getReceivingPartner()->getId(true),
                'Recipient-Address' => $this->getReceivingPartner()->getSendUrl()
            ]);
        }

        if ($message) {
            $url = $message->getHeaders()->getHeader('Receipt-Delivery-Option');
            if ($url && $this->getSendingPartner()) {
                $this->setUrl($url);
                $this->headerCollection->addHeader('Recipient-Address', $this->getSendingPartner()->getSendUrl());
            }
        }

        $this->setPath($this->adapter->getTempFilename());

        if ($message && $message->getHeaders()->getHeader('Disposition-Notification-Options')) {
            file_put_contents($this->getPath(), $container->toString(['canonical' => true, 'headers' => true]));
            $this->setPath($this->adapter->sign($this->getPath()));

            $content = file_get_contents($this->getPath());
            $this->headerCollection->addHeadersFromMessage($content);

            $mimePart = \Horde_Mime_Part::parseMessage($content);

            file_put_contents($this->getPath(), $mimePart->getContents());
        }
        else {
            file_put_contents($this->getPath(), $container->toString(['canonical' => true, 'headers' => false]));
        }

        return $this;
    }

    /**
     * Decode inbound MDN
     *
     * @return $this
     */
    public function decode() {
        $decoder = new \Mail_mimeDecode(file_get_contents($this->getPath()));
        $structure = $decoder->decode([
            'include_bodies' => true,
            'decode_headers' => true,
            'decode_bodies'  => true,
            'input'          => false,
            'crlf'           => "\n"
        ]);

        $this->setMessage('');
        $this->attributes = null;

        foreach ($structure->parts as $num => $part) {
            if (strtolower($part->headers['content-type']) == 'message/disposition-notification') {
                $this->attributes = $this->headerCollection->parseContent($part->body);
            }
            else {
                $this->setMessage(trim($part->body));
            }
        }

        return $this;
    }

    /**
     * Get MDN header attribute
     *
     * @param $key
     * @return bool
     */
    public function getAttribute($key) {
        return $this->attributes->getHeader($key);
    }

    /**
     * Get MDN message
     *
     * @return mixed
     */
    public function getMessage() {
        return $this->message;
    }

    /**
     * Get MDN delivery URL
     *
     * @return null|string
     */
    public function getUrl() {
        return $this->url;
    }

    /**
     * Set header attribute value for the MDN
     *
     * @param $key
     * @param $value
     * @return $this
     */
    public function setAttribute($key, $value) {
        $this->attributes->addHeader($key, $value);
        return $this;
    }

    /**
     * Set the message for the MDN
     *
     * @param string $message
     * @return $this
     */
    public function setMessage($message='') {
        $this->message = $message;
        return $this;
    }

    /**
     * Set MDN delivery URL
     *
     * @param $url
     * @return $this
     */
    public function setUrl($url) {
        $this->url = $url;
        return $this;
    }
}