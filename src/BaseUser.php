<?php

namespace mikk150\jwt;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use yii\di\Instance;
use yii\helpers\Json;
use yii\web\User;

abstract class BaseUser extends User
{
    public $jwkConfig;
    public $jwtConfig;

    public $signatureAlgorithms = [];

    public $idParam = 'uid';
    public $authTimeoutParam = 'exp';
    public $durationClaim = 'dur';

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
