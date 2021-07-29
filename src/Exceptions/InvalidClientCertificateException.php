<?php

namespace Kerattila\X509Auth\Exceptions;

use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * Class InvalidClientCertificateException
 * @package Kerattila\X509Auth\Exceptions
 */
class InvalidClientCertificateException extends UnauthorizedHttpException
{
}
