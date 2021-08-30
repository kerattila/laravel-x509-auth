<?php

namespace Kerattila\X509Auth\Console;

use Illuminate\Console\Command;
use Kerattila\X509Auth\Process\SignedCertificateGenerator;
use Symfony\Component\Console\Output\OutputInterface;

class GenerateSignedCertificate extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'x509auth:generate:signed-certificate {--dir=} {--private=} {--public=} ' .
                            '{--csr=} {--root-private=} {--root-public=} {--email=} {--numbits=} {--days=}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate signed certificate.';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $dir = $this->option('dir') ?? config('x509-auth.workdir');
        $publicKey = $this->option('public') ?? config('x509-auth.signed_cert.private_key_name');
        $privateKey = $this->option('private') ?? config('x509-auth.signed_cert.public_key_name');
        $csr = $this->option('csr') ?? config('x509-auth.signed_cert.csr_key_name');
        $numbits = $this->option('numbits') ?? config('x509-auth.signed_cert.numbits');
        $days = $this->option('days') ?? config('x509-auth.signed_cert.days');

        $rootPrivate = $this->option('root-private') ?? (config('x509-auth.root_ca.private_key_name') . '.key.pem');
        $rootPublic = $this->option('root-public') ?? (config('x509-auth.root_ca.public_key_name') . '.crt.pem');

        $subject = array_replace(config('x509-auth.signed_cert.subject'), [
            'emailAddress' => $this->option('email') ?? config('x509-auth.signed_cert.subject.emailAddress')
        ]);

        $password = (string)$this->secret('Type a password for the PKCS12 certificate:');
        (new SignedCertificateGenerator(
            $dir,
            $rootPrivate,
            $rootPublic,
            $password,
            $privateKey,
            $publicKey,
            $csr,
            $subject,
            config('x509-auth.signed_cert.alt_names'),
            $numbits,
            $days
        ))->generate(
            $this->getOutput()->getVerbosity() >= OutputInterface::VERBOSITY_VERBOSE
        );
    }
}
