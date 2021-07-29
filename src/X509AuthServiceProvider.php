<?php

namespace Kerattila\X509Auth;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Kerattila\X509Auth\Certificate\ClientCertificate;
use Kerattila\X509Auth\Console\GenerateRootCA;
use Kerattila\X509Auth\Console\GenerateSignedCertificate;

/**
 * Class X509AuthServiceProvider
 * @package Kerattila\X509Auth
 */
class X509AuthServiceProvider extends ServiceProvider
{
    /**
     * Boot up the serivce providers
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/x509-auth.php' => config_path('x509-auth.php'),
        ], 'config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                GenerateRootCA::class,
                GenerateSignedCertificate::class
            ]);
        }

        $this->registerMacro();
    }

    /**
     *
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/x509-auth.php',
            'x509-auth'
        );
    }

    /**
     * Register macro on Request class
     */
    public function registerMacro()
    {
        Request::macro('getClientCertificate', function () {
            $class = (string)config('x509-auth.certificate_class');
            return new $class($this);
        });
    }
}
