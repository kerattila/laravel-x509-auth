<?php

return [
    'workdir' => base_path(),
    'user_class' => \App\User::class,
    'certificate_class' => \Kerattila\X509Auth\Certificate\ClientCertificate::class,
    'middleware' => [
        'enabled' => true,
        'rules' => [
            /** SSL parameter === user field */
            'SSL_CLIENT_M_SERIAL' => 'username',
            'SSL_CLIENT_S_DN_Email' => 'email'
        ],
        'auto_login' => true
    ],
    'root_ca' => [
        'private_key_name' => 'root_ca_private',
        'public_key_name' => 'root_ca_public',
        'numbits' => 2048,
        'days' => 365,
        /** This will be converted to SSL subject /C=RO/ST=Mures/L=Targu Mures/O=ACME Corporation/CN=domain.com */
        'subject' => [
            'C' => 'RO', // 2 letter country code
            'ST' => 'Mures', // State
            'L' => 'Targu Mures', // Locality
            'O' => 'ACME Corporation', // Organzization
            'CN' => 'domain.com' // Common name
        ]
    ],
    'signed_cert' => [
        'private_key_name' => 'private',
        'public_key_name' => 'public',
        'csr_key_name' => 'csr',
        'numbits' => 2048,
        'days' => 365,
        /** This will be converted to SSL subject /C=RO/ST=Mures/L=Targu Mures/O=ACME Corporation/CN=domain.com */
        'subject' => [
            'C' => 'RO', // 2 letter country code
            'ST' => 'Mures', // State
            'L' => 'Targu Mures', // Locality
            'O' => 'ACME Corporation', // Organzization
            'OU' => 'IT Department', // Organizational unit
            'CN' => 'domain.com', // Common name
            'emailAddress' => 'email@domain.com', // Email address
        ],
        'alt_names' => [
            'domain.com',
            'domain.net',
            'domain.eu'
        ]
    ]
];
