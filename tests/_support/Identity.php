<?php

namespace tests;

use mikk150\jwt\ClaimIdentityInterface;
use yii\base\BaseObject;
use yii\web\IdentityInterface;

class Identity extends BaseObject implements IdentityInterface, ClaimIdentityInterface
{
    public function getClaims()
    {
        return [
            'custom_claim' => 'claim value'
        ];
    }

    public static function findIdentity($id)
    {
        return new static(['id' => $id]);
    }

    public static function findIdentityByAccessToken($token, $type = null)
    {
        throw new \Exception('Not implemented');
    }


    private $_id;
    public function getId()
    {
        return $this->_id;
    }

    public function setId(string $id)
    {
        $this->_id = $id;
    }

    public function getAuthKey()
    {
        throw new \Exception('Not implemented');
    }

    public function validateAuthKey($authKey)
    {
        throw new \Exception('Not implemented');
    }
    
}
