<?php

namespace mikk150\jwt;

use Exception;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\Exception\InvalidTokenException;
use yii\base\InvalidConfigException;
use yii\helpers\ArrayHelper;
use Yii;
use yii\base\Security;
use yii\di\Instance;
use yii\helpers\Json;
use yii\web\Cookie;

/**
*
*/
class User extends BaseUser
{
    public function init()
    {
        parent::init();

        if (!($this->getResponse() instanceof Response)) {
            throw new InvalidConfigException('application response object must be ' . Response::className());
        }

        if (!$this->jwkConfig || !$this->jwtConfig || !$this->signatureAlgorithms) {
            throw new InvalidConfigException('JOSE tokens are not configured');
        }
    }

    private $_response = 'response';
    public function setResponse($response)
    {
        $this->_response = $response;
    }

    /**
     * @return Response
     */
    public function getResponse()
    {
        if (!($this->_response instanceof Response)) {
            $this->_response = Instance::ensure($this->_response, Response::class);
        }
        return $this->_response;
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

    private $_security = 'security';
    public function setSecurity($security)
    {
        $this->_security = $security;
    }

    /**
     * @return security
     */
    public function getSecurity()
    {
        if (!($this->_security instanceof Security)) {
            $this->_security = Instance::ensure($this->_security, Security::class);
        }
        return $this->_security;
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
        $claim['jti'] = $this->getSecurity()->generateRandomString();

        if ($identity instanceof ClaimIdentityInterface) {
            /**
             * @var $identity ClaimIdentityInterface
             */
            $claim = ArrayHelper::merge($identity->getClaims(), $claim);
        }

        $cookie->value = $this->getTokenFromClaim($claim);
        $cookie->expire = time() + $duration;
        $this->getResponse()->getCookies()->add($cookie);
    }

    /**
     * Removes the identity cookie.
     * This method is used when [[enableAutoLogin]] is true.
     * @since 2.0.9
     */
    protected function removeIdentityCookie()
    {
        $this->getResponse()->getCookies()->remove(Yii::createObject(array_merge($this->identityCookie, [
            'class' => Cookie::class,
        ])));
    }

    protected function getTokenFromClaim(array $claim)
    {
        $serializer = new CompactSerializer();
        $algorithmManager = new AlgorithmManager($this->signatureAlgorithms);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jwk = new JWK($this->jwkConfig);

        $jws = $jwsBuilder->create()
            ->withPayload(Json::encode($claim))
            ->addSignature($jwk, $this->jwtConfig)
            ->build();

        return $serializer->serialize($jws);
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
        $value = $this->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        if (is_string($value)) {
            try {
                $data = $this->getClaimFromToken($value);
                if ($data !== null) {
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
            } catch (InvalidTokenException $ex) {
                return null;
            } catch (Exception $ex) {
                /**
                 * It's stupid, but they really do not have any way to specifically catch this exception
                 * as they do not have a separate exception class to it before 4.3.0 (Which is not even out)
                 */

                if ($ex::class === Exception::class && $ex->getMessage() === 'Unable to load and verify the token.') {
                    return null;
                }
                throw $ex;
            }
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
