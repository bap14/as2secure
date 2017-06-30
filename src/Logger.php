<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;

class Logger
{
    const LEVEL_INFO = 'info';
    const LEVEL_WARN = 'warn';
    const LEVEL_ERROR = 'error';
    const LEVEL_FATAL = 'fatal';

    protected $logFilePath;

    final public static function getInstance() {
        static $instance = null;
        if ($instance === null) {
            $instance = new self();
        }

        return $instance;
    }

    public function getLogFilePath() {
        return $this->logFilePath;
    }

    public function log($level, $message, $messageId=null) {
        $line = '[' . date('Y-m-d H:i:s') . '] ';
        if ($messageId) {
            $line .= trim($messageId, '<>') . ' ';
        }
        $line .= '(' . strtoupper($level) . ') ' . $message . PHP_EOL;

        file_put_contents($this->getLogFilePath() . DIRECTORY_SEPARATOR . 'events.log', $line, FILE_APPEND);

        return $this;
    }

    public function setLogFilePath($path) {
        $this->logFilePath = realpath($path);
    }

    /**
     * Logger constructor
     *
     * Use Logger::getInstance() to get a new (or the current) instance of the logger class.
     */
    private function __construct() {
        $this->setLogFilePath(realpath(dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . '_logs'));
    }
}