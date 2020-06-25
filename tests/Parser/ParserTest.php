<?php

namespace Test\Parser;

use PHPUnit\Framework\TestCase;
use TomCan\Csp\CspParser;

class ParserTest extends TestCase
{
    private string $prefix;

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

    public function testInvalidDirective(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $parser = new CspParser();
        $result = $parser->parse('invalid-src tom');
    }

    public function testPredefinedValues(): void
    {
        $parser = new CspParser();
        $predefinedSources = [  ];
        $result = $parser->parse("default-src 'none' 'self' 'unsafe-inline' 'unsafe-eval' 'invalid'");
        $this->assertCount(2, $result['default-src']);
        $result = $parser->parse("style-src 'none' 'self' 'unsafe-inline' 'unsafe-eval' 'invalid'");
        $this->assertCount(3, $result['style-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['style-src']);
        $result = $parser->parse("script-src 'none' 'self' 'unsafe-inline' 'unsafe-eval' 'invalid'");
        $this->assertCount(4, $result['script-src']);
        $this->assertArrayHasKey("'unsafe-inline'", $result['script-src']);
        $this->assertArrayHasKey("'unsafe-eval'", $result['script-src']);
    }
}