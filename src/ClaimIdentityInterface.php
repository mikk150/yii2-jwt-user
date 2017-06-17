<?php

namespace mikk150\jwt;

/**
*
*/
interface ClaimIdentityInterface extends \yii\web\IdentityInterface
{
    public function getClaims();
}
