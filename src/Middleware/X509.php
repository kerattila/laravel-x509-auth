<?php

namespace Kerattila\X509Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Kerattila\X509Auth\Certificate\ClientCertificate;
use Kerattila\X509Auth\Exceptions\InvalidClientCertificateException;
use Illuminate\Contracts\Auth\Factory as AuthFactory;

/**
 * Class X509
 * @package Kerattila\X509Auth\Middleware
 */
class X509
{
    /**
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $authFactory;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory $authFactory
     * @return void
     */
    public function __construct(AuthFactory $authFactory)
    {
        $this->authFactory = $authFactory;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ?string $guard = null)
    {
        $x509Enabled = config('x509-auth.middleware.enabled');
        if($x509Enabled) {
            /**
             * Validate certificate and check if there is any user
             * @var ClientCertificate $certificate
             */
            $certificate = $this->validateRequestCertificate($request);

            /**
             * Do actions after certificate has been validated
             * - log the user in
             * - extend to add cookie / create session / etc
             */
            $request = $this->postValidate($request, $next, $certificate, $guard);
        }

        return $next($request);
    }

    /**
     * @param $request
     * @return ClientCertificate|null
     */
    protected function validateRequestCertificate($request): ?ClientCertificate
    {
        /** @var ClientCertificate $certificate */
        $certificate = $request->getClientCertificate();
        if (!$certificate->isValid()) {
            throw new InvalidClientCertificateException('Certificate is not valid.');
        }

        $this->getUserByCertificate($certificate);

        return $certificate;
    }
    
    /**
     * Method called after certificate has been checked and it's valid
     * @param Request $request
     * @param Closure $next
     * @param ClientCertificate $certificate
     * @param string|null $guard
     * @return Request
     */
    protected function postValidate(
        Request $request,
        Closure $next,
        ClientCertificate $certificate,
        ?string $guard = null
    ): Request
    {
        $autoLogin = config('x509-auth.middleware.auto_login');
        if ($autoLogin) {
            $this->authFactory->guard($guard)->login(
                $this->getUserByCertificate($certificate),
                true
            );
        }
        return $request;
    }

    /**
     * @param ClientCertificate $certificate
     * @return mixed
     */
    protected function getUserByCertificate(ClientCertificate $certificate)
    {
        $rules = config('x509-auth.middleware.rules');
        $userClass = config('x509-auth.user_class');
        $userQuery = (new $userClass);
        foreach($rules as $certificateKey => $userField)
        {
            if (!$certificate->has($certificateKey)) {
                throw new InvalidClientCertificateException("Certificate missing \"$certificateKey\" key.");
            }
            $userQuery = $userQuery->where($userField, '=', $certificate->get($certificateKey));
        }
        if (!(($user = $userQuery->first()) && $user instanceof $userClass)) {
            throw new InvalidClientCertificateException("Certificate does not match any user.");
        }
        return $user;
    }
}
