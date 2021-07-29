<?php

namespace Kerattila\X509Auth\Process;

/**
 * Class RootCertificateGenerator
 * @package Kerattila\X509Auth\Process
 */
class RootCertificateGenerator extends AbstractCertificateGeneratorProcess
{
    /**
     * RootCertificateGenerator constructor.
     * @param string $outputDir
     * @param string $privateKeyName
     * @param string $publicKeyName
     * @param array $subject
     * @param int $numbits
     * @param int $days
     */
    public function __construct(
        string $outputDir,
        string $privateKeyName = 'root_ca_private',
        string $publicKeyName = 'root_ca_public',
        array $subject = [],
        int $numbits = 2048,
        int $days = 30
    )
    {
        parent::__construct(
            $outputDir,
            $privateKeyName,
            $publicKeyName,
            $subject,
            $numbits,
            $days
        );
    }

    /**
     * @param bool $verbose
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    public function generate(bool $verbose = false): void
    {
        $this->generatePrivateKey($verbose);
        $this->generatePublicKey($verbose);
    }

    /**
     * @param bool $verbose
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    protected function generatePrivateKey(bool $verbose = false): void
    {
        $this->runProcess([
            "openssl",
            "genrsa",
            "-out",
            $this->privateKeyPath,
            $this->numbits
        ], $verbose);
    }

    /**
     * @param bool $verbose
     * @throws \Kerattila\X509Auth\Exceptions\OpensslException
     */
    protected function generatePublicKey(bool $verbose = false): void
    {
        $this->runProcess([
            "openssl",
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key", $this->privateKeyPath,
            "-days", $this->days,
            "-out", $this->publicKeyPath,
            "-subj", $this->arrayToSubjectString($this->subject)
        ], $verbose);
    }
}
