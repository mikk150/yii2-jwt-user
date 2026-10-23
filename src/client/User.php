<?php

namespace mikk150\jwt\client;

use Exception;
use mikk150\jwt\BaseUser;
use yii\base\InvalidConfigException;
use Jose\Component\Core\Exception\InvalidTokenException;

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
        if (is_string($value)) {
            try {
                $data = $this->getClaimFromToken($value);
                if ($data !== null) {
                    return new $this->identityClass($data);
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
}
