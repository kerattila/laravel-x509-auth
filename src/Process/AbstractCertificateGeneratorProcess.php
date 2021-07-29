<?php

namespace Kerattila\X509Auth\Process;

/**
 * Class AbstractCertificateGeneratorProcess
 * @package Kerattila\X509Auth\Process
 */
abstract class AbstractCertificateGeneratorProcess extends AbstractProcess
{
    /**
     * @var int The size of the private key to generate in bits
     */
    protected int $numbits;
    /**
     * @var int This specifies the number of days to certify the certificate for
     */
    protected int $days;

    /**
     * @var array
     */
    protected array $subject;

    /**
     * AbstractCertificateGeneratorProcess constructor.
     * @param string $outputDir
     * @param string $privateKeyName
     * @param string $publicKeyName
     * @param array $subject
     * @param int $numbits
     * @param int $days
     */
    public function __construct(
        string $outputDir,
        string $privateKeyName,
        string $publicKeyName,
        array $subject,
        int $numbits = 2048,
        int $days = 30
    ) {
        parent::__construct($outputDir, $privateKeyName, $publicKeyName);
        $this->subject = $subject;
        $this->numbits = $numbits;
        $this->days = $days;
        return $this;
    }

    /**
     * @param array $subject
     * @return string
     */
    protected function arrayToSubjectString(array $subject) : string
    {
        $lines = array_map(fn($key) => sprintf('%s=%s', $key, addslashes($subject[$key])), array_keys($subject));
        if (!count($lines)) {
            return '';
        }
        return '/' . implode('/', $lines);
    }
}
