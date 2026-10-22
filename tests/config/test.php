<?php

return [
    'id' => 'test',
    'basePath' => dirname(__DIR__),
    'components' => [
        'response' => [
            'class' => mikk150\jwt\Response::class,
        ],
        'request' => [
            'cookieValidationKey' => 'test123'
        ]
    ]
];
