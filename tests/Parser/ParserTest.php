<?php

namespace Test\Parser;

use PHPUnit\Framework\TestCase;
use TomCan\Csp\Exception\CspInvalidDirectiveException;
use TomCan\Csp\CspParser;
use TomCan\Csp\Exception\CspInvalidSourceListItemException;

class ParserTest extends TestCase
{
    public function testParseEmpty(): void
    {
        $parser = new CspParser();
        $result = $parser->parse("");
        $this->assertIsArray($result);
        $this->assertCount(0, $result);
    }

    public function testBasicWithoutHeader(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('default-src tom');
        $this->assertIsArray($result);
        $this->assertCount(1, $result);
        $this->assertArrayHasKey('default-src', $result);
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
            $result = $parser->parse($header . 'default-src tom');
            $this->assertIsArray($result);
            $this->assertCount(1, $result);
            $this->assertArrayHasKey('default-src', $result);
        }
    }

    public function testReportOnly(): void
    {
        $parser = new CspParser();

        $result = $parser->parse( 'Content-Security-Policy: default-src tom');
        $this->assertIsArray($result);
        $this->assertCount(1, $result);
        $this->assertArrayHasKey('default-src', $result);
        $this->assertArrayNotHasKey('report', $result);

        $result = $parser->parse( 'Content-Security-Policy-Report-Only: default-src tom');
        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertArrayHasKey('default-src', $result);
        $this->assertArrayHasKey('report', $result);
        $this->assertArrayHasKey('report-only', $result['report']);
        $this->assertTrue($result['report']['report-only']);

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
            ];

        $parser = new CspParser();
        foreach ($directivesToTest as $directiveToTest) {
            $result = $parser->parse($directiveToTest.' tom');
            $this->assertIsArray($result);
            $this->assertCount(1, $result);
            $this->assertArrayHasKey($directiveToTest, $result);
        }
    }

    public function testMultipleDirectives(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('default-src tom;script-src \'self\'');
        $this->assertCount(2, $result);
        $this->assertArrayHasKey('default-src', $result);
        $this->assertArrayHasKey('script-src', $result);

        $result = $parser->parse('default-src tom ; script-src \'self\' ;');
        $this->assertCount(2, $result);
        $this->assertArrayHasKey('default-src', $result);
        $this->assertArrayHasKey('tom', $result['default-src']);
        $this->assertArrayHasKey('script-src', $result);
        $this->assertArrayHasKey('\'self\'', $result['script-src']);

    }

    public function testInvalidDirective(): void
    {
        $this->expectException(CspInvalidDirectiveException::class);
        $parser = new CspParser();
        $result = $parser->parse('invalid-src tom');
    }

    public function testPredefinedValues(): void
    {
        $parser = new CspParser();
        $result = $parser->parse("default-src 'none' 'self'");
        $this->assertCount(2, $result['default-src']);
        $result = $parser->parse("style-src 'none' 'self' 'unsafe-inline'");
        $this->assertCount(3, $result['style-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['style-src']);
        $result = $parser->parse("script-src 'none' 'self' 'unsafe-inline' 'unsafe-eval'");
        $this->assertCount(4, $result['script-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['script-src']);
        $this->assertArrayHasKey("'unsafe-eval'", $result['script-src']);
    }

    public function testInvalidPredefinedValuesStrict(): void
    {
        $parser = new CspParser();
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("default-src 'self' 'invalid'");
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("default-src 'self' 'unsafe-inline'");
    }

    public function testInvalidPredefinedValuesLoose(): void
    {
        $parser = new CspParser(CspParser::MODE_LOOSE);
        $result = $parser->parse("default-src 'self' 'invalid'");
        $this->assertCount(1, $result['default-src']);
        $result = $parser->parse("default-src 'self' 'unsafe-inline'");
        $this->assertCount(1, $result['default-src']);
        $result = $parser->parse("style-src 'self' 'unsafe-inline'");
        $this->assertCount(2, $result['style-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['style-src']);
        $result = $parser->parse("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
        $this->assertCount(3, $result['script-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['script-src']);
        $this->assertArrayHasKey("'unsafe-eval'", $result['script-src']);
    }

    public function testSandbox(): void
    {
        $parser = new CspParser();
        $result = $parser->parse('sandbox');
        $this->assertCount(1, $result);
        $this->assertCount(0, $result['sandbox']);
        $result = $parser->parse('sandbox allow-forms');
        $this->assertCount(1, $result);
        $this->assertCount(1, $result['sandbox']);
        $result = $parser->parse('sandbox allow-forms allow-same-origin allow-scripts allow-popups allow-modals allow-orientation-lock allow-pointer-lock allow-presentation allow-popups-to-escape-sandbox allow-top-navigation');
        $this->assertCount(10, $result['sandbox']);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse('sandbox invalid');
    }

    public function testNonceL2(): void
    {
        $parser = new CspParser(CspParser::MODE_STRICT, 2);
        $result = $parser->parse("style-src 'self' 'nonce-dmFsaWQgbm9uY2U='");
        $this->assertArrayHasKey("'nonce-dmFsaWQgbm9uY2U='", $result['style-src']);
        $result = $parser->parse("style-src 'self' 'nonce-not+valid+base64+but+valid+enough'");
        $this->assertArrayHasKey("'nonce-not+valid+base64+but+valid+enough'", $result['style-src']);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'nonce-inv#alid'");
    }

    public function testNonceL1(): void
    {
        $parser = new CspParser(CspParser::MODE_STRICT, 1);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'nonce-dmFsaWQgbm9uY2U='");
    }

    public function testShaL2(): void
    {
        $parser = new CspParser(CspParser::MODE_STRICT, 2);
        foreach (['sha256', 'sha384', 'sha512'] as $sha) {
            $result = $parser->parse("style-src '".$sha."-dmFsaWQgbm9uY2U='");
            $this->assertArrayHasKey("'".$sha."-dmFsaWQgbm9uY2U='", $result['style-src']);
        }
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'sha666-dmFsaWQgbm9uY2U=");
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'sha256-inv#alid'");
    }

    public function testShaL1(): void
    {
        $parser = new CspParser(CspParser::MODE_STRICT, 1);
        $this->expectException(CspInvalidSourceListItemException::class);
        $result = $parser->parse("style-src 'self' 'sha256-dmFsaWQgbm9uY2U='");
    }

}