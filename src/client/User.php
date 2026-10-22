<?php

namespace mikk150\jwt\client;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use mikk150\jwt\Request;
use mikk150\jwt\Response;
use yii\base\InvalidConfigException;
use Yii;
use yii\di\Instance;
use yii\helpers\Json;

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

        if (!$this->jwkConfig || !$this->jwtConfig || !$this->signatureAlgorithms) {
            throw new InvalidConfigException('JOSE tokens are not configured');
        }
    }

    private $_request = 'request';
    public function setRequest($request)
    {
        $this->_request = $request;
    }

    /**
     * @return Request
     */
    public function getRequest()
    {
        if (!($this->_request instanceof Request)) {
            $this->_request = Instance::ensure($this->_request, Request::class);
        }
        return $this->_request;
    }

    public function getIdentity($autoRenew = false)
    {
        $value = $this->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        $data = $this->getClaimFromToken($value);
        if ($data === null) {
            return null;
        }

        return new $this->identityClass($data);
    }

    protected function getClaimFromToken(string $token)
    {
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $algorithmManager = new AlgorithmManager($this->signatureAlgorithms);


        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        $jwk = new JWK($this->jwkConfig);

        $jwsLoader = new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            null
        );

        $jws = $jwsLoader->loadAndVerifyWithKey($token, $jwk, $signature);
        return Json::decode($jws->getPayload());
    }
}
