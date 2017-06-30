<?php
/**
 * Copyright (c) 2017 Brett Patterson
 *
 * @author   Brett Patterson <bap14@users.noreply.github.com>
 */

namespace Bap14\AS2Secure;
use Bap14\AS2Secure\Exception\CommandExecutionException;
use Bap14\AS2Secure\Exception\InvalidDataStructureException;
use Bap14\AS2Secure\Exception\Pkcs12BundleException;
use Bap14\AS2Secure\Exception\NoFilesProvidedException;

/**
 * Class Adapter
 *
 * @package Bap14\AS2Secure
 * @author Brett Patterson <bap14@users.noreply.github.com>
 * @license LGPL-3.0
 * @link None provided
 */
class Adapter
{
    /** @var string Path to directory containing AS2Secure.jar */
    protected $binDir;

    /** @var string Path to java executable */
    protected $javaPath;

    /** @var  Partner */
    protected $receivingPartner;

    /** @var  Partner */
    protected $sendingPartner;

    /** @var null|array */
    protected static $tmpFiles = null;

    /**
     * Adapter constructor.
     */
    public function __construct()
    {
        $this->javaPath = 'java';
        // Default to the composer "vendor/bin" directory above this module
        $this->jarPath  = realpath(dirname(dirname(dirname(dirname(__FILE__)))) . DIRECTORY_SEPARATOR . 'bin');
    }

    /**
     * Add file to list of files to be deleted on completion
     *
     * @param $file
     */
    public function addTempFileForDelete($file) {
        if (is_null(self::$tmpFiles)) {
            self::$tmpFiles = [];
            register_shutdown_function(array($this, 'deleteTempFiles'));
        }

        self::$tmpFiles[] = $file;
    }

    /**
     * Calculate the MIC checksum of a file
     *
     * @param $input Path to file to calculate checksum for
     * @param string $algorithm ALgorithm to use: sha1 or md5
     * @return string
     */
    public function calculateMicChecksum($input, $algorithm='sha1') {
        if (strtolower($algorithm) == 'sha1') {
            return base64_encode($this->hex2bin(sha1_file($input))) . ', sha1';
        } else {
            return base64_encode($this->hex2bin(md5_file($input))) . ', md5';
        }
    }

    /**
     * Compose a MIME message
     *
     * @param $files
     * @return bool|string
     * @throws NoFilesProvidedException
     */
    public function compose($files) {
        if (!is_array($files) || !count($files)) {
            throw new NoFilesProvidedException('At least one file must be provided');
        }

        $args = '';
        foreach ($files as $file) {
            $args .= ' -file ' . escapeshellarg($file['path']) .
                ' -mimetype ' . escapeshellarg($file['mimetype']) .
                ' -name ' . escapeshellarg($file['filename']);
        }

        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() .
            ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' compose' .
            implode(' ', $args) .
            ' -out ' . escapeshellarg($destinationFile);

        $this->exec($command);

        return $destinationFile;
    }

    /**
     * Compress a message
     *
     * @param $input
     * @return bool|string
     */
    public function compress($input) {
        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' compress ' .
            ' -in ' . escapeshellarg($input) .
            ' -out ' . escapeshellarg($destinationFile);

        $this->exec($command);
        return $destinationFile;
    }

    /**
     * Decompress a compressed message
     *
     * @param $input
     * @return bool|string
     */
    public function decompress($input) {
        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' decompress ' .
            ' -in ' . escapeshellarg($input) .
            ' -out ' . escapeshellarg($destinationFile);

        $this->exec($command);

        return $destinationFile;
    }

    /**
     * Decrypt a message
     *
     * @param $input
     * @return bool|string
     * @throws Pkcs12BundleException
     */
    public function decrypt($input) {
        $privateKey = $this->receivingPartner->getPrivateKeyFile();
        if (!$privateKey) {
            throw new Pkcs12BundleException('Unable to extract private key from PKCS12 bundle');
        }

        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' smime ' .
            ' -decrypt ' .
            ' -in ' . escapeshellarg($input) .
            ' -inkey ' . escapeshellarg($privateKey) .
            ' -out ' . escapeshellarg($destinationFile);

        $this->exec($command);

        return $destinationFile;
    }

    /**
     * Delete temporary files
     */
    public function deleteTempFiles() {
        foreach (self::$tmpFiles as $file) {
            @unlink($file);
        }
    }

    /**
     * Detect mime type of file
     *
     * @param string $file Path to file
     * @return string
     */
    public function detectMimeType($file) {
        $fileInfo = finfo_open(FILEINFO_MIME);
        $mimeType = finfo_file($fileInfo, $file);
        finfo_close($fileInfo);
        return $mimeType;
    }

    /**
     * Execute a shell command
     *
     * @param $command
     * @param bool $returnOutput
     * @return array|int
     * @throws CommandExecutionException
     */
    public function exec($command, $returnOutput=false) {
        $output = [];
        $returnVar = 0;

        exec($command, $output, $exitCode);
        if ($exitCode) {
            $message = 'Unexpected error in command: ' . $command;
            if ($output) {
                $message = $output[0];
            }

            throw new CommandExecutionException($message);
        }

        if ($returnOutput) {
            return $output;
        }

        return $returnVar;
    }

    /**
     * Extract files attached to message
     *
     * @param $input
     * @return array
     * @throws InvalidDataStructureException
     */
    public function extract($input) {
        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' extract ' .
            ' -in ' . escapeshellarg($input) .
            ' -out ' . escapeshellarg($destinationFile);

        $results = $this->exec($command, true);

        $files = [];

        foreach ($results as $tmp) {
            $tmp = explode(';', $tmp);
            if (count($tmp <= 1)) {
                continue;
            }
            else if (count($tmp) != 3) {
                throw new InvalidDataStructureException('Uneexpected data structure while extracting message');
            }

            $file = [
                'path'     => trim($tmp[0], '"'),
                'mimetype' => trim($tmp[1], '"'),
                'filename' => trim($tmp[2], '"')
            ];

            $this->addTempFileForDelete($file['path']);
        }

        return $files;
    }

    /**
     * Get directory where AS2Secure.jar file is located
     *
     * @return string
     */
    public function getBinDir() {
        return $this->binDir;
    }

    /**
     * Get path to `java` executable
     *
     * @return string
     */
    public function getJavaPath() {
        return $this->javaPath;
    }

    /**
     * Get MIC checksum of file.
     *
     * @param $input Path of file to get checksum for
     * @return bool|mixed
     */
    public function getMicChecksum($input) {
        try {
            $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
                ' checksum' .
                ' -in ' . escapeshellarg($input) .
                ' 2>/dev/null';

            $result = $this->exec($command, true);
            return $result[0];
        }
        catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Generate a temporary file name
     *
     * @return bool|string
     */
    public function getTempFilename() {
        if (is_null(self::$tmpFiles)) {
            self::$tmpFiles = array();
            register_shutdown_function(array($this, 'deleteTempFiles'));
        }

        $filename = tempnam(sys_get_temp_dir(), 'as2file_');
        self::$tmpFiles[] = $filename;

        return $filename;
    }

    /**
     * Convert string from hexadecimal to binary
     *
     * @param string $string
     * @return string
     */
    public function hex2bin($string) {
        $bin = '';
        $characters = str_split($string);
        for ($i=0; $i < count($characters); ) {
            $bin .= chr(hexdec($characters[$i] . $characters[$i + 1]));
            $i += 2;
        }

        return $bin;
    }

    /**
     * Set the directory where `AS2Secure.jar` can be found
     *
     * @param $path
     * @return $this
     */
    public function setBinDir($path) {
        $this->binDir = $path;
        return $this;
    }

    /**
     * Set the path to a specific `java`
     *
     * @param $path
     * @return $this
     */
    public function setJavaPath($path) {
        $this->javaPath = $path;
        return $this;
    }

    /**
     * Set the receiving partner identity.
     *
     * @param Partner $partner
     * @return $this
     */
    public function setReceivingPartner(Partner $partner)
    {
        $this->receivingPartner = $partner;
        $this->receivingPartner->setAdapter($this);
        return $this;
    }

    /**
     * Set the sending partner identity.
     *
     * @param Partner $partner
     * @return $this
     */
    public function setSendingPartner(Partner $partner)
    {
        $this->sendingPartner = $partner;
        $this->sendingPartner->setAdapter($this);
        return $this;
    }

    /**
     * Sign an outgoing message using private key from PKCS12 bundle
     *
     * @param $input
     * @param bool $useZlib
     * @param string $encoding
     * @return bool|string
     * @throws Pkcs12BundleException
     */
    public function sign($input, $useZlib=false, $encoding='base64') {
        if (!$this->sendingPartner->getSecPkcs12Password()) {
            throw new Pkcs12BundleException('Missing PKCS12 bundle to sign outgoing messages');
        }

        $password = ' -nopassword';
        if ($this->sendingPartner->getSecPkcs12Password()) {
            $password = ' -password ' . escapeshellarg($this->sendingPartner->getSecPkcs12Password());
        }

        $compress = ($useZlib ? ' -compress' : '');

        $pkcs12Bundle = $this->sendingPartner->getSecPkcs12File();

        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' sign ' .
            ' -pkcs12 ' . $pkcs12Bundle .
            $password .
            $compress .
            ' -encoding ' . escapeshellarg($encoding) .
            ' -in ' . escapeshellarg($input) .
            ' -out ' . escapeshellarg($destinationFile) .
            ' > /dev/null';

        $this->exec($command);

        return $destinationFile;
    }

    /**
     * Verify message received
     *
     * @param $input
     * @return bool|string
     */
    public function verify($input) {
        if ($this->sendingPartner->getSecPkcs12()) {
            $security = ' -pkcs12 ' . escapeshellarg($this->sendingPartner->getSecPkcs12());
            if ($this->sendingPartner->getSecPkcs12Password()) {
                $security .= ' -password ' . escapeshellarg($this->sendingPartner->getSecPkcs12Password());
            }
        } else {
            $security = ' -cert ' . escapeshellarg($this->sendingPartner->getSecCertificateFile());
        }

        $destinationFile = $this->getTempFilename();

        $command = $this->getJavaPath() . ' -jar ' . escapeshellarg($this->getJarPath()) .
            ' verify ' .
            $security .
            ' -in ' . escapeshellarg($input) .
            ' -out ' . escapeshellarg($destinationFile) .
            ' > /dev/null 2>&1';

        $this->exec($command);

        return $destinationFile;
    }

    protected function getJarPath() {
        return $this->getBinDir() . DIRECTORY_SEPARATOR . 'AS2Secure.jar';
    }
}