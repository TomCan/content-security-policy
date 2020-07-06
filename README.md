# tomcan/content-security-policy
A PHP Content-Security-Policy library

## Usage
Install through composer  

```# composer require tomcan/content-security-policy```

```php
<?php
require __DIR__ . '/vendor/autoload.php';
$csp = new \TomCan\Csp\ContentSecurityPolicy();
$csp->addToDirective(\TomCan\Csp\ContentSecurityPolicy::DIRECTIVE_DEFAULT_SRC, 'self');
echo $csp; // default-src: 'self';
```