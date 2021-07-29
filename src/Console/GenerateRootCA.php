<?php

namespace Kerattila\X509Auth\Console;

use Illuminate\Console\Command;
use Kerattila\X509Auth\Process\RootCertificateGenerator;
use Symfony\Component\Console\Output\OutputInterface;

class GenerateRootCA extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'x509auth:generate:root-ca {--dir=} {--private=} {--public=}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate Root certificate.';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $dir = $this->option('dir') ?? config('x509-auth.workdir');
        $privateKey = $this->option('private') ?? config('x509-auth.root_ca.private_key_name');
        $publicKey = $this->option('public') ?? config('x509-auth.root_ca.public_key_name');
        (new RootCertificateGenerator(
            $dir,
            $privateKey,
            $publicKey,
            config('x509-auth.root_ca.subject')
        ))->generate(
                $this->getOutput()->getVerbosity() >= OutputInterface::VERBOSITY_VERBOSE
            );
    }
}
