<?php
require('../vendor/autoload.php');

define('EPIC_API_KEY', getenv('DATABASE_URL'));
define('EPIC_API_SECRET', getenv('DATABASE_URL'));
// define('HEROKU_API_KEY',     '');
// define('HEROKU_API_SECRET',  '');

$app = new Silex\Application();
$app['debug'] = true;

$app->register(new Gigablah\Silex\OAuth\OAuthServiceProvider(), array(
    'oauth.services' => array(
        // 'EPIC' => array(
        //     'key' => EPIC_API_KEY,
        //     'secret' => EPIC_API_SECRET,
        //     // 'scope' => array('email'),
        //     // 'user_endpoint' => 'https://graph.facebook.com/me'
        // ),
        'Heroku' => array(
            'key' => HEROKU_API_KEY,
            'secret' => HEROKU_API_SECRET,
            'scope' => array(),
            // Note: permission needs to be obtained from Twitter to use the include_email parameter
            'user_endpoint' => '',
            'user_callback' => function ($token, $userInfo, $service) {
                $token->setUser($userInfo['name']);
                $token->setEmail($userInfo['email']);
                $token->setUid($userInfo['id']);
            }
        ),
        'Google' => array(
            'key' => GOOGLE_API_KEY,
            'secret' => GOOGLE_API_SECRET,
            'scope' => array(
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ),
            'user_endpoint' => 'https://www.googleapis.com/oauth2/v1/userinfo'
        )
    )
));
// Provides URL generation
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());

// Provides CSRF token generation
// You will have to include symfony/form in your composer.json
$app->register(new Silex\Provider\FormServiceProvider());

// Provides session storage
$app->register(new Silex\Provider\SessionServiceProvider(), array(
    'session.storage.save_path' => '/tmp'
));

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
    'security.firewalls' => array(
        'default' => array(
            'pattern' => '^/',
            'anonymous' => true,
            'oauth' => array(
                //'login_path' => '/auth/{service}',
                //'callback_path' => '/auth/{service}/callback',
                //'check_path' => '/auth/{service}/check',
                'failure_path' => '/login',
                'with_csrf' => true
            ),
            'logout' => array(
                'logout_path' => '/logout',
                'with_csrf' => true
            ),
            // OAuthInMemoryUserProvider returns a StubUser and is intended only for testing.
            // Replace this with your own UserProvider and User class.
            'users' => new Gigablah\Silex\OAuth\Security\User\Provider\OAuthInMemoryUserProvider()
        )
    ),
    'security.access_rules' => array(
        array('^/auth', 'ROLE_USER')
    )
));


$dbopts = parse_url(getenv('DATABASE_URL'));
$app->register(new Herrera\Pdo\PdoServiceProvider(),
               array(
                   'pdo.dsn' => 'pgsql:dbname='.ltrim($dbopts["path"],'/').';host='.$dbopts["host"] . ';port=' . $dbopts["port"],
                   'pdo.username' => $dbopts["user"],
                   'pdo.password' => $dbopts["pass"]
               )
);

// Register the monolog logging service
$app->register(new Silex\Provider\MonologServiceProvider(), array(
  'monolog.logfile' => 'php://stderr',
));

// Register view rendering
$app->register(new Silex\Provider\TwigServiceProvider(), array(
    'twig.path' => __DIR__.'/views',
));

// Our web handlers
$app->before(function (Symfony\Component\HttpFoundation\Request $request) use ($app) {
    if (isset($app['security.token_storage'])) {
        $token = $app['security.token_storage']->getToken();
    } else {
        $token = $app['security']->getToken();
    }

    $app['user'] = null;

    if ($token && !$app['security.trust_resolver']->isAnonymous($token)) {
        $app['user'] = $token->getUser();
    }
});

$app->get('/login', function (Symfony\Component\HttpFoundation\Request $request) use ($app) {
    $app['monolog']->addDebug('logging output for login.');
    $services = array_keys($app['oauth.services']);

    return $app['twig']->render('login.twig', array(
        'login_paths' => $app['oauth.login_paths'],
        'logout_path' => $app['url_generator']->generate('logout', array(
            '_csrf_token' => $app['oauth.csrf_token']('logout')
        )),
        'error' => $app['security.last_error']($request)
    ));
});

$app->match('/logout', function () {})->bind('logout');

$app->get('/', function() use($app) {
  $app['monolog']->addDebug('logging output.');
  return $app['twig']->render('index.twig');
});

$app->get('/cowsay', function() use($app) {
  $app['monolog']->addDebug('cowsay');
  return "<pre>".\Cowsayphp\Cow::say("Cool beans")."</pre>";
});

$app->get('/hello', function() use($app) {
  $app['monolog']->addDebug('logging output.');
  return str_repeat('Hello', getenv('TIMES'));
});

// $app->get('/login', function() use($app) {
//   $app['monolog']->addDebug('logging output for login.');
//   return $app['twig']->render("login.twig");
// });

$app->get('/provider', function() use($app) {
  $app['monolog']->addDebug('logging output for login.');
  return $app['twig']->render("provider.twig");
});

$app->get('/patient', function() use($app) {
  $app['monolog']->addDebug('logging output for login.');
  return $app['twig']->render("patient.twig");
});

$app->get('/db/', function() use($app) {
  $st = $app['pdo']->prepare('SELECT name FROM test_table');
  $st->execute();

  $names = array();
  while ($row = $st->fetch(PDO::FETCH_ASSOC)) {
    $app['monolog']->addDebug('Row ' . $row['name']);
    $names[] = $row;
  }

  return $app['twig']->render('database.twig', array(
    'names' => $names
  ));
});

$app->get('/auth/redirect', function() use($app) {
  $st = $app['pdo']->prepare('SELECT name FROM test_table');
  $st->execute();

  $names = array();
  while ($row = $st->fetch(PDO::FETCH_ASSOC)) {
    $app['monolog']->addDebug('Row ' . $row['name']);
    $names[] = $row;
  }
});

$app->run();
