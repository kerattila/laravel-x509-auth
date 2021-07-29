<?php

namespace Kerattila\X509Auth\Process;

use Kerattila\X509Auth\Exceptions\OpensslException;

/**
 * Class SignedCertificateGenerator
 * @package Kerattila\X509Auth\Process
 */
class SignedCertificateGenerator extends AbstractCertificateGeneratorProcess
{
    /**
     * @var string
     */
    protected string $csrName;
    /**
     * @var string
     */
    protected string $fullChainPath;
    /**
     * @var string
     */
    protected string $pkcs12Path;
    /**
     * @var string
     */
    protected string $pkcs12Password;
    /**
     * @var string
     */
    protected string $csrPath;
    /**
     * @var array
     */
    protected array $altNames;
    /**
     * @var string
     */
    protected string $rootCaPrivateKeyName;
    /**
     * @var string
     */
    protected string $rootCaPrivateKeyPath;
    /**
     * @var string
     */
    protected string $rootCaPublicKeyName;
    /**
     * @var string
     */
    protected string $rootCaPublicKeyPath;

    /**
     * @var array
     */
    protected array $tempFiles = [];

    /**
     * SignedCertificateGenerator constructor.
     * @param string $outputDir
     * @param string $rootCaPrivateKeyName
     * @param string $rootCaPublicKeyName
     * @param string $pkcs12Password
     * @param string $privateKeyName
     * @param string $publicKeyName
     * @param string $csrName
     * @param array $subject
     * @param array $altNames
     * @param int $numbits
     * @param int $days
     */
    public function __construct(
        string $outputDir,
        string $rootCaPrivateKeyName,
        string $rootCaPublicKeyName,
        string $pkcs12Password,
        string $privateKeyName = 'private',
        string $publicKeyName = 'public',
        string $csrName = 'csr',
        array $subject = [],
        array $altNames = [],
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
        $this->csrName = $csrName;
        $this->csrPath = $this->buildPathTo("$csrName.pem");

        $this->fullChainPath = $this->buildPathTo("$privateKeyName-fullchain.pem");
        $this->pkcs12Path = $this->buildPathTo("$privateKeyName.pfx");
        $this->pkcs12Password = $pkcs12Password;

        $this->rootCaPrivateKeyName = $rootCaPrivateKeyName;
        $this->rootCaPrivateKeyPath = $this->buildPathTo($rootCaPrivateKeyName);

        $this->rootCaPublicKeyName = $rootCaPublicKeyName;
        $this->rootCaPublicKeyPath = $this->buildPathTo($rootCaPublicKeyName);

        $this->altNames = $altNames;
    }

    /**
     * @param bool $verbose
     */
    public function generate(bool $verbose = false): void
    {
        $this->generatePrivateKey($verbose);
        $this->generateCSR($verbose);
        $this->generatePublicKey($verbose);
        $this->buildFullChainCertificate(
            $this->publicKeyPath,
            $this->rootCaPublicKeyPath
        );
        $this->generatePKCS12Certificate($verbose);

        $this->cleanupFiles(
            ...$this->tempFiles
        );
    }

    /**
     * @param bool $verbose
     * @throws OpensslException
     */
    public function generatePrivateKey(bool $verbose): void
    {
        $this->runProcess([
            "openssl", "genrsa", '-out', $this->privateKeyPath
        ], $verbose);
    }

    /**
     * @param bool $verbose
     * @throws OpensslException
     */
    public function generateCSR(bool $verbose): void
    {
        $configFilePath = $this->generateConfigFile();
        $this->runProcess([
            "openssl",
            "req",
            "-new",
            "-key", $this->privateKeyPath,
            "-out", $this->csrPath,
            "-in", $this->csrPath,
            "-subj", $this->arrayToSubjectString($this->subject),
            "-config", $configFilePath,
        ], $verbose);
        $this->tempFiles[] = $this->csrPath;
        $this->tempFiles[] = $configFilePath;
    }

    /**
     * @param bool $verbose
     * @throws OpensslException
     */
    public function generatePublicKey(bool $verbose): void
    {
        $v3ConfigFilePath = $this->generateV3ConfigFile();
        $this->runProcess([
            "openssl",
            "x509",
            "-req",
            "-in", $this->csrPath,
            "-CA", $this->rootCaPublicKeyPath,
            "-CAkey", $this->rootCaPrivateKeyPath,
            "-CAcreateserial",
            "-out", $this->publicKeyPath,
            "-days", $this->days,
            "-sha256",
            "-extfile", $v3ConfigFilePath,
        ], $verbose);
        $this->tempFiles[] = $v3ConfigFilePath;
    }

    /**
     * @param bool $verbose
     * @throws OpensslException
     */
    protected function generatePKCS12Certificate(bool $verbose): void
    {
        $this->runProcess([
            "openssl",
            "pkcs12",
            "-export",
            "-out", $this->pkcs12Path,
            "-inkey", $this->privateKeyPath,
            "-in", $this->fullChainPath,
            "-certfile", $this->rootCaPrivateKeyPath,
            "-passout", "pass:" . $this->pkcs12Password
        ], $verbose);
    }

    /**
     * @return string
     */
    protected function generateConfigFile(): string
    {
        $configFileName = $this->buildPathTo(time() . ".cnf");
        $configData = <<<CONFIG
[req]
default_bits = 4096
prompt = no
encrypt_key = no
default_md = sha256
distinguished_name = distinguished_name
req_extensions = req_ext

[distinguished_name]
CN = {$this->subject['CN']}
emailAddress = {$this->subject['emailAddress']}
O = {$this->subject['O']}
OU = {$this->subject['OU']}
L = {$this->subject['L']}
ST = {$this->subject['ST']}
C = {$this->subject['C']}

[req_ext]
subjectAltName = @alt_names

[alt_names]
CONFIG;
        if (count($this->altNames)) {
            foreach ($this->altNames as $i => $altName) {
                $configData .= "\nDNS." . ($i + 1) . " = $altName";
            }
        }
        file_put_contents($configFileName, $configData);
        return $configFileName;
    }

    /**
     * @return string
     */
    protected function generateV3ConfigFile(): string
    {
        $configFileName = $this->buildPathTo(time() . ".cnf");
        $configData = <<<CONFIG
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
CONFIG;
        if (count($this->altNames)) {
            foreach ($this->altNames as $i => $altName) {
                $configData .= "\nDNS." . ($i + 1) . " = $altName";
            }
        }
        file_put_contents($configFileName, $configData);
        return $configFileName;
    }

    /**
     *
     */
    protected function buildFullChainCertificate()
    {
        $files = func_get_args();
        foreach ($files as $file) {
            if (!file_exists($file)) {
                throw new \LogicException("Full chain generation failed. \"$file\" not found.");
            }
            file_put_contents(
                $this->fullChainPath,
                file_get_contents($file),
                FILE_APPEND
            );
        }
    }

    /**
     *
     */
    protected function cleanupFiles(): void
    {
        $files = func_get_args();
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
}
