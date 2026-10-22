<?php

namespace tests\unit;

use mikk150\jwt\Response;
use mikk150\jwt\SelfSignedCookie;

class SelfSignedCookieTest extends \Codeception\Test\Unit
{
    /**
     * @var \mikk150\jwt\tests\UnitTester
     */
    protected $tester;

    protected function _before()
    {
    }

    protected function _after()
    {
    }

    // tests
    public function testAddingSelfSignedCookie()
    {
        $cookie = new SelfSignedCookie([
            'name' => 'selfsignedcookie',
            'value' => 'value',
            'domain' => '',
            'expire' => 0,
            'path' => '/',
            'secure' => false,
            'httpOnly' => true,
        ]);

        /**
         * @var        \mikk150\jwt\Response
         */
        $response = new Response([
            'charset' => 'utf8'
        ]);
        $response->cookies->add($cookie);

        $this->assertContains($cookie, $response->cookies);
    }
}
