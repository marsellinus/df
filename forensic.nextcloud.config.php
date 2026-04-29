<?php
$CONFIG = [
  'log_type'         => 'file',
  'logfile'          => '/var/log/nextcloud/nextcloud.log',
  'loglevel'         => 1,   // 1=info (skip debug noise), 2=warn, 3=error
  'logtimezone'      => 'UTC',
  'logdateformat'    => 'Y-m-d\\TH:i:sP',
  'log_rotate_size'  => 104857600,

  'filelocking.enabled' => true,
  'memcache.local'      => '\\OC\\Memcache\\APCu',
  'memcache.locking'    => '\\OC\\Memcache\\Redis',
  'redis' => ['host' => 'nc-redis', 'port' => 6379],

  'trusted_proxies' => ['nc-web'],
];
