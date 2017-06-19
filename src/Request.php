<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

use Bap14\AS2Secure\Exception\MethodNotAvailableException;
use Bap14\AS2Secure\Message\MessageAbstract;

class Request extends MessageAbstract
{
    public function decode() {
        throw new MethodNotAvailableException('Method "decode" is not available on a Request message.');
    }

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

    public function encode() {
        throw new MethodNotAvailableException('Method "encode" is not available on a Request message.');
    }

    public function getObject() {
        $content = $this->getHeaders()->__toString() . "\n\n";
        $content .= file_get_contents($this->getPath());
        $input = $this->adapter->getTempFilename();
    }

    public function getUrl() {
        throw new MethodNotAvailableException('Method "getUrl" is not available on a Request message.');
    }
}