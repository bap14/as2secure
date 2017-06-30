<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\UnsignedMdnException;
use Bap14\AS2Secure\Message\MessageAbstract;

class MDN extends MessageAbstract
{
    const ACTION_AUTO    = 'automatic-action';
    const ACTION_MANUAL  = 'manual-action';
    const MODE_AUTO      = 'MDN-sent-automatically';
    const MODE_MANUAL    = 'MDN-sent-manually';
    const TYPE_PROCESSED = 'processed';
    const TYPE_FAILED    = 'failed';
    const MOD_ERROR      = 'error';
    const MOD_WARN       = 'warning';

    protected $url;

    public function __construct($data=null, $params=[]) {
        parent::__construct();

        $this->headerCollection->addHeader('action-mode', self::ACTION_AUTO)
            ->addHeader('sending-mode', self::MODE_AUTO);

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

        }
        else if ($data instanceof \Horde_Mime_Part) {

        }
        else {

        }
    }

    public function encode() {
    }

    public function decode() {
        // TODO: Implement decode() method.
    }

    public function getUrl() {
        return $this->url;
    }
}