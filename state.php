<?php
require __DIR__ . '/lib.php';
start_session();
$state = enter_page('state');
json_exit(200, ['state' => $state, 'next' => SESSION_STATES[$state]['home'], 'actions' => SESSION_STATES[$state]['actions']]);
