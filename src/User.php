<?php

namespace mikk150\jwt;

use yii\base\Component;
use yii\base\InvalidConfigException;
use Yii;

/**
*
*/
class User extends \yii\web\User
{
    public function init()
    {
        parent::init();

        if (!(Yii::$app->response instanceof Response)) {
            throw new InvalidConfigException('application response object must be ' . Response::className());
        }
    }
}
