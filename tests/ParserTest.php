<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use TomCan\Csp\ContentSecurityPolicy;
use TomCan\Csp\Exception\CspInvalidDirectiveException;
use TomCan\Csp\CspParser;
use TomCan\Csp\Exception\CspInvalidSourceListItemException;

class ParserTest extends TestCase
{
    public function testParseEmpty(): void
    {
        $parser = new CspParser();
        $result = $parser->parse("");
        $this->assertCount(0, $result->getDirectives());
    }

    public function testBasicWithoutHeader(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('default-src https://www.tom.be');
        $this->assertCount(1, $result->getDirectives());
        $this->assertArrayHasKey(ContentSecurityPolicy::DIRECTIVE_DEFAULT_SRC, $result->getDirectives());
    }

    public function testBasicWithHeader(): void
    {
        $parser = new CspParser();
        $headers = [
            "Content-Security-Policy: ",
            "Content-Security-Policy:",
            "Content-Security-Policy:           ",
            "CoNtEnT-SeCuRiTy-PoLiCy: ",
        ];
        foreach ($headers as $header) {
            $result = $parser->parse($header . 'default-src https://www.tom.be');
            $this->assertCount(1, $result->getDirectives());
            $this->assertArrayHasKey(ContentSecurityPolicy::DIRECTIVE_DEFAULT_SRC, $result->getDirectives());
        }
    }

    public function testReportOnly(): void
    {
        $parser = new CspParser();

        $result = $parser->parse( 'Content-Security-Policy: default-src https://www.tom.be');
        $this->assertCount(1, $result->getDirectives());
        $this->assertArrayHasKey(ContentSecurityPolicy::DIRECTIVE_DEFAULT_SRC, $result->getDirectives());
        $this->assertFalse($result->isReportOnly());

        $result = $parser->parse( 'Content-Security-Policy-Report-Only: default-src https://www.tom.be');
        $this->assertCount(1, $result->getDirectives());
        $this->assertArrayHasKey(ContentSecurityPolicy::DIRECTIVE_DEFAULT_SRC, $result->getDirectives());
        $this->assertTrue($result->isReportOnly());
    }

    public function testBasicDirectives(): void
    {
        $directivesToTest = [
                'default-src',
                'script-src',
                'style-src',
                'img-src',
                'font-src',
                'connect-src',
                'media-src',
                'object-src',
                'frame-src',
                'report-to',
                'worker-src',
                'manifest-src',
                'prefetch-src',
            ];

        $parser = new CspParser();
        foreach ($directivesToTest as $directiveToTest) {
            $result = $parser->parse($directiveToTest.' https://www.tom.be');
            $this->assertCount(1, $result->getDirectives());
            $this->assertArrayHasKey($directiveToTest, $result->getDirectives());
        }
    }

    public function testMultipleDirectives(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('default-src https://www.tom.be;script-src \'self\'');
        $this->assertCount(2, $result->getDirectives());
        $this->assertArrayHasKey('default-src', $result->getDirectives());
        $this->assertArrayHasKey('script-src', $result->getDirectives());

        $result = $parser->parse('default-src https://www.tom.be ; script-src \'self\' ;');
        $this->assertCount(2, $result->getDirectives());
        $this->assertArrayHasKey('default-src', $result->getDirectives());
        $this->assertArrayHasKey('script-src', $result->getDirectives());

        $result = $parser->parse('default-src https://www.tom.be ; ;; ; ;; ;; ;; ;script-src \'self\' ;');
        $this->assertCount(2, $result->getDirectives());
        $this->assertArrayHasKey('default-src', $result->getDirectives());
        $this->assertArrayHasKey('script-src', $result->getDirectives());
    }

    public function testInvalidDirective(): void
    {
        $this->expectException(CspInvalidDirectiveException::class);
        $parser = new CspParser();
        $result = $parser->parse('invalid-src https://www.tom.be');
    }

    public function testPredefinedValues(): void
    {
        $parser = new CspParser();
        $result = $parser->parse("default-src 'none'");
        $this->assertCount(1, $result->getDirective('default-src'));

        $result = $parser->parse("default-src 'self'");
        $this->assertCount(1, $result->getDirective('default-src'));

        $result = $parser->parse("style-src 'self' 'unsafe-inline'");
        $this->assertCount(2, $result->getDirective('style-src'));
        $this->assertArrayHasKey("'unsafe-inline'", $result->getDirective('style-src'));
        $result = $parser->parse("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
        $this->assertCount(3, $result->getDirective('script-src'));
        $this->assertArrayHasKey("'unsafe-inline'", $result->getDirective('script-src'));
        $this->assertArrayHasKey("'unsafe-eval'", $result->getDirective('script-src'));
    }

    public function testInvalidPredefinedValuesStrictInvalid(): void
    {
        $parser = new CspParser();
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("default-src 'self' 'invalid'");
    }

    public function testInvalidPredefinedValuesStrictInvalidForThis(): void
    {
        $parser = new CspParser();
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("default-src 'self' 'unsafe-inline'");
    }

    public function testInvalidPredefinedValuesStrictInvalidForNotAllowed(): void
    {
        $parser = new CspParser();
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("report-to 'my-endpoint'");
    }

    public function testInvalidPredefinedValuesLoose(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_LOOSE);
        $result = $parser->parse("default-src 'self' 'invalid'");
        $this->assertCount(1, $result->getDirective('default-src'));

        $result = $parser->parse("default-src 'self' 'unsafe-inline'");
        $this->assertCount(1, $result->getDirective('default-src'));

        $result = $parser->parse("style-src 'self' 'unsafe-inline'");
        $this->assertCount(2, $result->getDirective('style-src'));
        $this->assertArrayHasKey("'unsafe-inline'", $result->getDirective('style-src'));

        $result = $parser->parse("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
        $this->assertCount(3, $result->getDirective('script-src'));
        $this->assertArrayHasKey("'unsafe-inline'", $result->getDirective('script-src'));
        $this->assertArrayHasKey("'unsafe-eval'", $result->getDirective('script-src'));
    }

    public function testSandbox(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('sandbox');
        $this->assertCount(0, $result->getDirective('sandbox'));

        $result = $parser->parse('sandbox allow-forms');
        $this->assertCount(1, $result->getDirective('sandbox'));

        $result = $parser->parse('sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-modals allow-orientation-lock allow-pointer-lock allow-presentation allow-popups-to-escape-sandbox allow-top-navigation');
        $this->assertCount(10, $result->getDirective('sandbox'));
        $this->assertArrayHasKey('allow-forms', $result->getDirective('sandbox'));
        $this->assertArrayHasKey('allow-orientation-lock', $result->getDirective('sandbox'));

        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse('sandbox invalid');
    }

    public function testNonceL2(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        $result = $parser->parse("style-src 'self' 'nonce-dmFsaWQgbm9uY2U='");
        $this->assertArrayHasKey("'nonce-dmFsaWQgbm9uY2U='", $result->getDirective('style-src'));

        $result = $parser->parse("style-src 'self' 'nonce-not+valid+base64+but+valid+enough'");
        $this->assertArrayHasKey("'nonce-not+valid+base64+but+valid+enough'", $result->getDirective('style-src'));

        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'nonce-inv#alid'");
    }

    public function testShaL2(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        foreach (['sha256', 'sha384', 'sha512'] as $sha) {
            $result = $parser->parse("style-src '" . $sha . "-dmFsaWQgbm9uY2U='");
            $this->assertArrayHasKey("'" . $sha . "-dmFsaWQgbm9uY2U='", $result->getDirective('style-src'));
        }
    }

    public function testShaL2InvalidAlgo(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'sha666-dmFsaWQgbm9uY2U='");
    }

    public function testShaL2InvalidBase64(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'sha256-inv#alid'");
    }

    public function testScriptPredefinedL3(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        $result = $parser->parse("script-src 'strict-dynamic' 'unsafe-hashes'");
        $this->assertArrayHasKey("'strict-dynamic'", $result->getDirective('script-src'));
        $this->assertArrayHasKey("'unsafe-hashes'", $result->getDirective('script-src'));
    }

    public function testWorkerManifestPrefetchPredefined(): void
    {
        $parser = new CspParser(ContentSecurityPolicy::MODE_STRICT);
        foreach (['worker-src', 'prefetch-src', 'manifest-src'] as $directive) {
            $result = $parser->parse($directive . " 'self' 'unsafe-hashes'");
            $this->assertArrayHasKey("'self'", $result->getDirective($directive));
            $this->assertArrayHasKey("'unsafe-hashes'", $result->getDirective($directive));
        }
    }

}