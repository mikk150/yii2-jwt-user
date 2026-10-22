<?php

namespace tests\unit;

use Exception;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\HS256;
use mikk150\jwt\Request;
use mikk150\jwt\Response;
use mikk150\jwt\User;
use tests\Identity;
use yii\base\Security;
use yii\web\CookieCollection;
use yii\web\IdentityInterface;

class UserTest extends TestCase
{
    public function testLoadingIdentityMadeByUser()
    {
        $response = new Response([
            'charset' => 'utf8'
        ]);
        $this->mockWebApplication([
            'components' => [
                'response' => $response,
                'security' => Security::class,
            ],
        ]);

        $user = new User([
            'identityClass' => Identity::class,
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
        ]);

        $user->switchIdentity($this->makeEmpty(IdentityInterface::class, [
            'getId' => 'test_id'
        ]), 3200);

        $identityCookie = $response->getCookies()->get($user->identityCookie['name']);


        $response = new Response([
            'charset' => 'utf8'
        ]);

        $request = $this->construct(Request::class, [
            [
                'user' => $user,
                'enableCsrfCookie' => false,
            ]
        ], [
            'getCookies' => function () use ($identityCookie) {
                $collection = new CookieCollection();
                $collection->add($identityCookie);
                return $collection;
            }
        ]);

        $this->mockWebApplication([
            'components' => [
                'response' => $response,
                'security' => Security::class,
                'request' => $request
            ],
        ]);

        $user = new User([
            'response' => $response,
            'security' => Security::class,
            'identityClass' => Identity::class,
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
        ]);

        $this->assertEquals('test_id', $user->getId());
    }

    public function testLoadingInvalidJWT()
    {
        $response = new Response([
            'charset' => 'utf8'
        ]);
        $this->mockWebApplication([
            'components' => [
                'response' => $response,
                'security' => Security::class,
            ],
        ]);

        $user = new User([
            'identityClass' => Identity::class,
            'enableAutoLogin' => true,
            'jwkConfig' => [
                'kty' => 'oct',
                'alg' => 'HS256',
                'k' => Base64UrlSafe::encode('invalidinvalidinvalidinvalidinval'),
            ],
            'jwtConfig' => [
                'alg'  => 'HS256',
            ],
            'signatureAlgorithms' => [
                new HS256()
            ]
        ]);

        $user->switchIdentity(new Identity(['id' => 'test_id']), 3200);

        $identityCookie = $response->getCookies()->get($user->identityCookie['name']);


        $response = new Response([
            'charset' => 'utf8'
        ]);

        $request = $this->construct(Request::class, [
            [
                'user' => $user,
                'enableCsrfCookie' => false,
            ]
        ], [
            'getCookies' => function () use ($identityCookie) {
                $collection = new CookieCollection();
                $collection->add($identityCookie);
                return $collection;
            }
        ]);

        $this->mockWebApplication([
            'components' => [
                'response' => $response,
                'security' => Security::class,
                'request' => $request
            ],
        ]);

        $user = new User([
            'response' => $response,
            'security' => Security::class,
            'identityClass' => Identity::class,
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
        ]);
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unable to load and verify the token.');
        $this->assertEquals('test_id', $user->getId());
    }
}
