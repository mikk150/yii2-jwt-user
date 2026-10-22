<?php

namespace mikk150\jwt;

use yii\web\Cookie;
use yii\base\InvalidConfigException;
use yii\base\Security;
use yii\di\Instance;

/**
*
*/
class Request extends \yii\web\Request
{
    public $selfSignedCookies = [];

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

    private $_user = 'user';
    public function setUser($user)
    {
        $this->_user = $user;
    }

    /**
     * @return User
     */
    public function getUser()
    {
        if (!($this->_user instanceof User)) {
            $this->_user = Instance::ensure($this->_user, User::class);
        }
        return $this->_user;
    }

    public function init()
    {
        parent::init();

        $this->selfSignedCookies[] = $this->getUser()->identityCookie['name'];
    }

    /**
     * Converts `$_COOKIE` into an array of [[Cookie]].
     * @return array the cookies obtained from request
     * @throws InvalidConfigException if [[cookieValidationKey]] is not set when [[enableCookieValidation]] is true
     */
    protected function loadCookies()
    {
        $cookies = [];
        if ($this->enableCookieValidation) {
            if ($this->cookieValidationKey == '') {
                throw new InvalidConfigException(get_class($this) . '::cookieValidationKey must be configured with a secret key.');
            }
            foreach ($_COOKIE as $name => $value) {
                if (!is_string($value)) {
                    continue;
                }
                if (!in_array($name, $this->selfSignedCookies)) {
                    $data = $this->getSecurity()->validateData($value, $this->cookieValidationKey);
                    if ($data === false) {
                        continue;
                    }
                }
                $data = @unserialize($data);
                if (is_array($data) && isset($data[0], $data[1]) && $data[0] === $name) {
                    $cookies[$name] = new Cookie([
                        'name' => $name,
                        'value' => $data[1],
                        'expire' => null,
                    ]);
                } else if (in_array($name, $this->selfSignedCookies)) {
                    $cookies[$name] = new SelfSignedCookie([
                        'name' => $name,
                        'value' => $value,
                        'expire' => null,
                    ]);
                }
            }
        } else {
            foreach ($_COOKIE as $name => $value) {
                $cookies[$name] = new Cookie([
                    'name' => $name,
                    'value' => $value,
                    'expire' => null,
                ]);
            }
        }

        return $cookies;
    }
}
