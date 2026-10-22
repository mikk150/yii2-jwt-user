<?php

namespace tests;

use yii\base\BaseObject;
use yii\web\IdentityInterface;

class ClientIdentity extends BaseObject implements IdentityInterface
{
    public $custom_claim;

    public $uid;

    public $exp;

    public $dur;
    public $jti;

    public static function findIdentity($id)
    {
        return new static(['uid' => $uid]);
    }

    public static function findIdentityByAccessToken($token, $type = null)
    {
        throw new \Exception('Not implemented');
    }


    public function getId()
    {
        return $this->uid;
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
