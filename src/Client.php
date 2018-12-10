<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;
use Bap14\AS2Secure\Exception\InvalidMessageException;
use Bap14\AS2Secure\Message\HeaderCollection;
use Bap14\AS2Secure\Message\MessageAbstract;

/**
 * Class Client
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Client
{
    /** @var  Request */
    protected $request;

    /** @var Response */
    protected $response;

    public function __construct() {
        $this->response = new Response();
    }

    public function getResponse() {
        return $this->response;
    }

    public function sendRequest($request) {
        if (!($request instanceof MessageAbstract)) {
            throw new InvalidMessageException('Unexpected message type received.  Expected Message or MDN.');
        }

        $this->request = $request;

        $headers = $request->getHeaders()->toArray();

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $request->getUrl(),
            CURLOPT_HEADER         => false,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_INTERFACE      => AS2_IP,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_BINARYTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 10,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FRESH_CONNECT  => true,
            CURLOPT_FORBID_REUSE   => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $request->getContents(),
            CURLOPT_USERAGENT      => Adapter::getServerSignature(),
            CURLOPT_HEADERFUNCTION => array($this->response, 'curlHeaderHandler')
        ]);

        $auth = $request->getAuthentication();
        if ($auth->hasAuthentication()) {
            curl_setopt_array($ch, [
                CURLOPT_HTTPAUTH => $auth->getMethod(),
                CURLOPT_USERPWD  => urlencode($auth->getUsername()) . ':' . urlencode($auth->getPassword())
            ]);
        }

        $this->response->handle($ch);

        if (
            $request instanceof MessageAbstract &&
            $request->getReceivingPartner()->getMdnRequest() == Partner::ACKNOWLEDGE_SYNC
        ) {
            $this->response->sendMDN();
        }

        return $this;
    }
}
