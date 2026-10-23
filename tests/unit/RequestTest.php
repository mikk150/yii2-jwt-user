<?php

namespace tests\unit;

use Codeception\Test\Unit;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\HS256;
use mikk150\jwt\client\User;
use mikk150\jwt\Request;
use tests\ClientIdentity;
use yii\base\Security;

class RequestTest extends Unit
{
    public function testLoadingYii2Cookies()
    {
        $security = new Security();
        $cookieSecurityKey = 'verysecure';
        $_COOKIE = [
            'test' => $security->hashData(serialize(['test', 'value']), $cookieSecurityKey)
        ];

        $request = new Request([
            'cookieValidationKey' => $cookieSecurityKey,
            'security' => $security,
            'user' => new User([
                'identityClass' => ClientIdentity::class,
                'enableAutoLogin' => true,
                'jwkConfig' => [
                    'kty' => 'oct',
                    'alg' => 'HS256',
                    'k' => Base64UrlSafe::encode('verysecrettokenverysecrettokenver'),
                ],
                'jwtConfig' => [
                    'alg'  => 'HS256',
                ],
                'signatureAlgorithms' => [
                    new HS256()
                ]
            ])
        ]);

        $cookie = $request->cookies->get('test');
        $this->assertEquals('value', $cookie->value);
    }

    public function testLoadingYii2InvalidCookies()
    {
        $security = new Security();
        $cookieSecurityKey = 'verysecure';
        $_COOKIE = [
            'test' => $security->hashData(serialize(['test', 'value']), 'wrongKey')
        ];

        $request = new Request([
            'cookieValidationKey' => $cookieSecurityKey,
            'security' => $security,
            'user' => new User([
                'identityClass' => ClientIdentity::class,
                'enableAutoLogin' => true,
                'jwkConfig' => [
                    'kty' => 'oct',
                    'alg' => 'HS256',
                    'k' => Base64UrlSafe::encode('verysecrettokenverysecrettokenver'),
                ],
                'jwtConfig' => [
                    'alg'  => 'HS256',
                ],
                'signatureAlgorithms' => [
                    new HS256()
                ]
            ])
        ]);

        $this->assertNull($request->cookies->get('test'));
    }

    public function testLoadingSelfSignedCookie()
    {
        $security = new Security();
        $cookieSecurityKey = 'verysecure';
        $_COOKIE = [
            'test' => 'selfSignedCookie'
        ];

        $request = new Request([
            'cookieValidationKey' => $cookieSecurityKey,
            'security' => $security,
            'selfSignedCookies' => ['test'],
            'user' => new User([
                'identityClass' => ClientIdentity::class,
                'enableAutoLogin' => true,
                'jwkConfig' => [
                    'kty' => 'oct',
                    'alg' => 'HS256',
                    'k' => Base64UrlSafe::encode('verysecrettokenverysecrettokenver'),
                ],
                'jwtConfig' => [
                    'alg'  => 'HS256',
                ],
                'signatureAlgorithms' => [
                    new HS256()
                ]
            ])
        ]);

        $cookie = $request->cookies->get('test');
        $this->assertEquals('selfSignedCookie', $cookie->value);
    }
}
