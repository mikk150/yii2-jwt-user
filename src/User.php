<?php

namespace mikk150\jwt;

use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\helpers\ArrayHelper;
use Jose\Factory\JWKFactory;
use Jose\Factory\CheckerManagerFactory;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\JWTLoader;
use Jose\JWTCreator;
use Jose\Signer;
use Yii;

/**
*
*/
class User extends \yii\web\User
{
    public $jwkConfig;
    public $jwtConfig;

    public $signatureAlgorithms;

    public $idParam = 'uid';
    public $authTimeoutParam = 'exp';
    public $durationClaim = 'dur';

    public function init()
    {
        parent::init();

        if (!(Yii::$app->getResponse() instanceof Response)) {
            throw new InvalidConfigException('application response object must be ' . Response::className());
        }

        if (!$this->jwkConfig || !$this->jwtConfig || !$this->signatureAlgorithms) {
            throw new InvalidConfigException('JOSE tokens are not configured');
        }
    }

    /**
     * Switches to a new identity for the current user.
     *
     * When [[enableSession]] is true, this method may use session and/or cookie to store the user identity information,
     * according to the value of `$duration`. Please refer to [[login()]] for more details.
     *
     * This method is mainly called by [[login()]], [[logout()]] and [[loginByCookie()]]
     * when the current user needs to be associated with the corresponding identity information.
     *
     * @param IdentityInterface|null $identity the identity information to be associated with the current user.
     * If null, it means switching the current user to be a guest.
     * @param int $duration number of seconds that the user can remain in logged-in status.
     * This parameter is used only when `$identity` is not null.
     */
    public function switchIdentity($identity, $duration = 0)
    {
        $this->setIdentity($identity);

        if (!$this->enableSession) {
            return;
        }

        /* Ensure any existing identity cookies are removed. */
        if ($this->enableAutoLogin) {
            $this->removeIdentityCookie();
        }

        if ($identity) {
            if ($duration > 0 && $this->enableAutoLogin) {
                $this->sendIdentityCookie($identity, $duration);
            }
        }
    }

    /**
     * Sends an identity cookie.
     * This method is used when [[enableAutoLogin]] is true.
     * It saves [[id]], [[IdentityInterface::getAuthKey()|auth key]], and the duration of cookie-based login
     * information in the cookie.
     * @param \yii\web\IdentityInterface|ClaimIdentityInterface $identity
     * @param int $duration number of seconds that the user can remain in logged-in status.
     * @see loginByCookie()
     */
    protected function sendIdentityCookie($identity, $duration)
    {
        $cookie = new SelfSignedCookie($this->identityCookie);

        $claim = [];


        $claim[$this->idParam] = $identity->getId();
        $claim[$this->authTimeoutParam] = time() + $duration;
        $claim[$this->durationClaim] = $duration;
        $claim['jti'] = Yii::$app->security->generateRandomString();

        if ($identity instanceof ClaimIdentityInterface) {
            /**
             * @var $identity ClaimIdentityInterface
             */
            $claim = ArrayHelper::merge($identity->getClaims(), $claim);
        }

        $cookie->value = $this->getToken($claim);
        $cookie->expire = time() + $duration;
        Yii::$app->getResponse()->getCookies()->add($cookie);
    }


    protected function getToken($claim)
    {
        $jwk = JWKFactory::createFromValues($this->jwkConfig);

        $signer = new Signer($this->signatureAlgorithms);

        $jwt = new JWTCreator($signer);

        return $jwt->sign($claim, $this->jwtConfig, $jwk);
    }

    /**
     * Determines if an identity cookie has a valid format and contains a valid auth key.
     * This method is used when [[enableAutoLogin]] is true.
     * This method attempts to authenticate a user using the information in the identity cookie.
     * @return array|null Returns an array of 'identity' and 'duration' if valid, otherwise null.
     * @see loginByCookie()
     * @since 2.0.9
     */
    protected function getIdentityAndDurationFromCookie()
    {
        $value = Yii::$app->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        $data = $this->getClaim($value);
        if ($data === null) {
            return null;
        }
        if (isset($data[$this->idParam]) && isset($data[$this->authTimeoutParam])) {
            $class = $this->identityClass;
            /* @var $identity IdentityInterface */
            $identity = $class::findIdentity($data[$this->idParam]);
            if ($identity !== null) {
                $this->setClaims($data);
                return ['identity' => $identity, 'duration' => $data[$this->durationClaim]];
            }
        }
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

    private $_claims = [];
    protected function setClaims($claims)
    {
        $this->_claims = $claims;
    }

    public function getClaims()
    {
        return $this->_claims;
    }
}
