<?php

/**
 * SignInWithAppleProviderTest.php
 *
 * @author: Leonard Smith <leonard@acornwebconsultants.com>
 * Date: 3/28/20
 * Time: 7:56 AM
 */

namespace GeneaLabs\LaravelSignInWithApple\Unit;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use GeneaLabs\LaravelSignInWithApple\Providers\SignInWithAppleProvider;
use GeneaLabs\LaravelSignInWithApple\Tests\UnitTestCase;
use Illuminate\Support\Facades\Config;
use Laravel\Socialite\Facades\Socialite;
use InvalidArgumentException;
use GuzzleHttp\Client;
use Mockery;

class SignInWithAppleProviderTest extends UnitTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        Config::set('services.sign_in_with_apple.app_id', 'com.example.myapp');
    }

    public function testThatVerifyJwtDataSucceeds()
    {
        $data = [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'com.example.myapp'
        ];

        $this->assertTrue(Socialite::driver('sign-in-with-apple')->verifyJwtData($data));
    }

    public function testThatVerifyJwtDataFailsWithBadIssuer()
    {
        $data = [
            'iss' => 'https://someotherissuer.com',
            'aud' => 'com.example.myapp'
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid issuer.');

        Socialite::driver('sign-in-with-apple')->verifyJwtData($data);
    }

    public function testThatVerifyJwtDataFailsWithBadAudience()
    {
        $data = [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'com.someotherdomain.myapp'
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('App Id does not match aud variable in JWT.');

        Socialite::driver('sign-in-with-apple')->verifyJwtData($data);
    }

    public function testUserFromJwt()
    {
        $driver = Socialite::driver('sign-in-with-apple');

        $mock = Mockery::mock(Client::class);
        $mock->shouldReceive('get')
            ->once()
            ->andReturn($mock);

        $mock->shouldReceive('getBody')
            ->once()
            ->andReturn($this->publicKeyArray());

        $driver->setHttpClient($mock);

        $jwt = $this->getSignedJwt();

        $user = $driver->userFromJwt($jwt);

        $this->assertEquals('joe@anywhere.com', $user->getEmail());
        $this->assertEquals('001659.d0c393f689b245ac9eb18cbbc66ea9e6.1853', $user->getId());
    }

    private function publicKeyArray()
    {
        return <<<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "86D88Kf",
      "use": "sig",
      "alg": "RS256",
      "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "eXaunmL",
      "alg": "RS256",
      "n": "mlmmSB2i3Kq4w0FMUa3APEuJcqkC6cflZX5wFp8jjVRyjCvuX6WuN8PFAZiIchotqaZruJAQIIY40dfBgPY-3vYHBybtI3gS_e0oo1_9FiTmeu0DihkkARP4yDMaz2z1GCwBfCQvy33YXMf0Hb-JKOCwTG-PtX3TqnNtwUOD_eO6RH5RuSB3GWi7FxDKapJOO0cnvGQrmKe2Jmnx4-_cW5eujWZYOHjvPWxPKU-Oj0ODOSBqtOdSaWHCUUysbQwBbsNz6c0JCcB9sZXYPQI_-HIrdLP6WbEIriA3W0PHLnXsb8ehUovSl_d5n4M52F9XG0POvatMXM2hQMgLCHnHKw"
    }
  ]
}
EOF;
    }

    private function getSignedJwt()
    {
        $payload = [
            "iss" => "https://appleid.apple.com",
            "aud" => "com.example.myapp",
            "exp" => Carbon::now()->addMinutes(10)->unix(),
            "iat" => Carbon::now()->unix(),
            "sub" => "001659.d0c393f689b245ac9eb18cbbc66ea9e6.1853",
            "c_hash" => "JOBcza1317twAeMX_rDZVA",
            "email" => "joe@anywhere.com",
            "email_verified" => "true",
            "auth_time" => Carbon::now()->unix(),
            "nonce_supported" => true
        ];

        return JWT::encode($payload, $this->pemPrivateKey(), 'RS256', 'eXaunmL');
    }

    private function pemPublicKey()
    {
        return <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmlmmSB2i3Kq4w0FMUa3A
PEuJcqkC6cflZX5wFp8jjVRyjCvuX6WuN8PFAZiIchotqaZruJAQIIY40dfBgPY+
3vYHBybtI3gS/e0oo1/9FiTmeu0DihkkARP4yDMaz2z1GCwBfCQvy33YXMf0Hb+J
KOCwTG+PtX3TqnNtwUOD/eO6RH5RuSB3GWi7FxDKapJOO0cnvGQrmKe2Jmnx4+/c
W5eujWZYOHjvPWxPKU+Oj0ODOSBqtOdSaWHCUUysbQwBbsNz6c0JCcB9sZXYPQI/
+HIrdLP6WbEIriA3W0PHLnXsb8ehUovSl/d5n4M52F9XG0POvatMXM2hQMgLCHnH
KwIDAQAB
-----END PUBLIC KEY-----
EOF;

    }

    private function pemPrivateKey()
    {
        return <<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAmlmmSB2i3Kq4w0FMUa3APEuJcqkC6cflZX5wFp8jjVRyjCvu
X6WuN8PFAZiIchotqaZruJAQIIY40dfBgPY+3vYHBybtI3gS/e0oo1/9FiTmeu0D
ihkkARP4yDMaz2z1GCwBfCQvy33YXMf0Hb+JKOCwTG+PtX3TqnNtwUOD/eO6RH5R
uSB3GWi7FxDKapJOO0cnvGQrmKe2Jmnx4+/cW5eujWZYOHjvPWxPKU+Oj0ODOSBq
tOdSaWHCUUysbQwBbsNz6c0JCcB9sZXYPQI/+HIrdLP6WbEIriA3W0PHLnXsb8eh
UovSl/d5n4M52F9XG0POvatMXM2hQMgLCHnHKwIDAQABAoIBAEk6Bv1nsgBmrklU
DVUizXTNkWPocw1eXKKOHbddwIwoaD/AB9Mw0zp5kllzeChJ6yf1YF2rWztS8ln7
tj3slV9J8YOfIBoXuUrm3MTFoViEISRolalKzB4Gz5yLQkjuNElHd1zh/hrYlXFP
G62RVQ0jrABXXSKJk4XmRUfPNCuaxgEnio33Q7zubzlm6sUNNW/8APz/cI0UYXSf
ufjPgVmqnybvWi9iZVytd7kLWF+kIJ7PdI2Dg28C4hctRpJfHVrWPNslMIDMoY+s
6eq3B1W2wNiqibzlLmUBr88pxCVTQOV+l+XZoYjS5PZoaoqINLcyD/tNkumw6NGb
rpLW2GECgYEAyIapZKsWYXjxVsZLMEVdMQ8cp36JRqoXLz129RAZULB4plgMshJI
5TBpAZT+LLuFdozdMFdV1muYOIDa+vkWnA64A8XgIgxkmF66zDbMWxi024QzlxY2
kpPl1C1rrSoV7Z9MpsIUQJMmHYvEYxb6O7eikxu5L0drTGtVlMFpU6UCgYEAxQzL
xcjUOPbFFUYmOwfc7YGm89ViHFLPPxJOIQSihjEQ7enxRTNKclRCiLWGCGKkIL0f
3I9dX8dT0kDSaE7tIbYr+tlgs/UujveCAwlEAY3H/rHdeU0rhe0Kj03ozhxKVs8q
zgARzsu0sSLiTTJWdRMl3fShq1VxdemIdfXedo8CgYEAri9LNYboCgNkoFvfNC8M
pHDcEyJ3XEqjmQVrL7SsSMsCAny5inUXnP5QOG+T2oeJh1EVUciLZ5ZOw8YqcZet
bCHc9moMJ4dcWn7vBDUVjowHjidoKPXCsdCG86gAwIquQZr+mlw7+1vW4BNopCpx
cy4wqliKo+cF7XvO+0iGlYECgYBt8ijUr6yyKAZpS13TfByqLLhRvtLiSNY4M+eC
BssEIuZ2SR0E5ox4ZElHbDlf/mHjnoLjlt6brWU4oFCGQNuQ/stlSNrrLjePL8zM
EuRuFYTsuKOBpixNqqhEs0zdi+1yqF8S1/kXsJOebn9kYVzaMBfl0zRNm/wVtXsd
jlVVQwKBgQCYZfNMj/6x6Av/+Y9dRjKvtW53LgG41/M2EiQjYi6qhzwtGH316eqA
82urEzVuYANJYcrCFQsNckrXWyjWk6ZTzga6WqFlLVJWtPxbddtMl6mXh1espa3g
QMFhZGpca22SZfotVZDZPD1auHs8VwdeSk63N3MFTSc9+qu4GxUI6A==
-----END RSA PRIVATE KEY-----
EOF;
    }
}


