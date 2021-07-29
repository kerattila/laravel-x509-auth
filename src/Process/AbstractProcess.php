<?php

namespace Kerattila\X509Auth\Process;

use Kerattila\X509Auth\Exceptions\OpensslException;
use Symfony\Component\Process\Process as SymfonyProcess;

/**
 * Class AbstractProcess
 * @package Kerattila\X509Auth\Process
 */
abstract class AbstractProcess
{
    /**
     * @var string Output/working directory
     */
    protected string $outputdir;
    /**
     * @var string Filename of the private key; eg. private.pem
     */
    protected string $privateKeyName;
    /**
     * @var string This is the full path for to the private key (incl. filename)
     */
    protected string $privateKeyPath;
    /**
     * @var string Filename of the public key; eg. public.crt
     */
    protected string $publicKeyName;
    /**
     * @var string This is the full path for to the public key (incl. filename)
     */
    protected string $publicKeyPath;

    /**
     * AbstractProcess constructor.
     * @param string $outputDir
     * @param string $privateKeyName
     * @param string $publicKeyName
     */
    public function __construct(
        string $outputDir,
        string $privateKeyName,
        string $publicKeyName
    ) {
        $this->checkOutputDir($outputDir);
        $this->outputdir = $outputDir;
        $this->privateKeyName = $privateKeyName;
        $this->publicKeyName = $publicKeyName;
        $this->privateKeyPath = $this->buildPathTo("$this->privateKeyName.key.pem");
        $this->publicKeyPath = $this->buildPathTo("$this->publicKeyName.crt.pem");
        return $this;
    }

    /**
     * @param string $file
     * @return string
     */
    protected function buildPathTo(string $file) : string
    {
        return rtrim($this->outputdir, '\/') . DIRECTORY_SEPARATOR . $file;
    }

    /**
     * @param string $dir
     */
    protected function checkOutputDir(string $dir)
    {
        if (!is_dir($dir)) {
            throw new \LogicException("Output path is not a valid directory");
        }
    }

    /**
     * @param array $params
     * @param bool $verbose
     * @return bool|null
     * @throws OpensslException
     */
    protected function runProcess(array $params, bool $verbose = false) : ?bool
    {
        $privateKeyProcess = (new SymfonyProcess($params));
        $privateKeyProcess->setTty(true);
        if (!$verbose) {
            $privateKeyProcess->disableOutput();
        }
        $exitCode = $privateKeyProcess->run();
        if ($exitCode === 0) {
            return true;
        } else {
            throw new OpensslException(
                'An error ocurred while running OpenSSL command. Try running process with verbose.'
            );
        }
    }

    /**
     * @param bool $verbose
     */
    abstract public function generate(bool $verbose = false): void;
}
