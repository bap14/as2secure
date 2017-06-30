<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Message\MessageAbstract;

class Message extends MessageAbstract
{
    public function encode() {
        // TODO: Implement encode() method.
    }

    public function encrypt() {

    }

    public function decode() {
        // TODO: Implement decode() method.
    }

    public function generateMDN($exception=null) {

    }

    public function getUrl() {
        return $this->getReceivingPartner()->getSendUrl();
    }
}