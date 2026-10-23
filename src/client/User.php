<?php

namespace mikk150\jwt\client;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use mikk150\jwt\BaseUser;
use mikk150\jwt\Request;
use mikk150\jwt\Response;
use yii\base\InvalidConfigException;
use Yii;
use yii\di\Instance;
use yii\helpers\Json;

class User extends BaseUser
{
    /**
     * @var string the class name of the [[identity]] object.
     */
    public $identityClass = 'mikk150\jwt\client\Identity';

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

    public function getIdentity($autoRenew = false)
    {
        $value = $this->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        $data = $this->getClaimFromToken($value);
        if ($data === null) {
            return null;
        }

        return new $this->identityClass($data);
    }
}
