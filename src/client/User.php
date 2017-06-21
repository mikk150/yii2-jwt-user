<?php

namespace mikk150\jwt\client;

use mikk150\jwt\Response;
use mikk150\jwt\Request;
use yii\base\InvalidConfigException;
use Jose\Factory\JWKFactory;
use Jose\Factory\CheckerManagerFactory;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\JWTLoader;
use Jose\JWTCreator;
use Jose\Signer;
use Yii;

class User extends \yii\web\User
{
    /**
     * @var string the class name of the [[identity]] object.
     */
    public $identityClass = 'mikk150\jwt\client\Identity';

    public $jwkConfig;
    public $jwtConfig;

    public $signatureAlgorithms;

    public $idParam = 'uid';
    public $authTimeoutParam = 'exp';

    public function init()
    {
        \yii\base\Component::init();

        if ($this->enableAutoLogin && !isset($this->identityCookie['name'])) {
            throw new InvalidConfigException('User::identityCookie must contain the "name" element.');
        }

        if (!(Yii::$app->getResponse() instanceof Response)) {
            throw new InvalidConfigException('application response object must be ' . Response::className());
        }

        if (!$this->jwkConfig || !$this->jwtConfig || !$this->signatureAlgorithms) {
            throw new InvalidConfigException('JOSE tokens are not configured');
        }
    }

    public function getIdentity($autoRenew = false)
    {
        $value = Yii::$app->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        $data = $this->getClaim($value);
        if ($data === null) {
            return null;
        }

        return new $this->identityClass($data);
    }

    protected function getClaim($token)
    {
        $jwk = JWKFactory::createFromValues($this->jwkConfig);
        $loader = new Loader();

        try {
            $jws = $loader->loadAndVerifySignatureUsingKey($token, $jwk, $this->signatureAlgorithms);
            return $jws->getPayload();
        } catch (\InvalidArgumentException $e) {
        }
    }
}
