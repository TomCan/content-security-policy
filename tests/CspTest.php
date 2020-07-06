<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use TomCan\Csp\ContentSecurityPolicy;

class CspTest extends TestCase
{

    public function testConstructor()
    {
        foreach ([ContentSecurityPolicy::MODE_STRICT, ContentSecurityPolicy::MODE_LOOSE] as $mode) {
            $csp = new ContentSecurityPolicy($mode);
            $this->assertEquals($mode, $csp->getMode());
        }
    }

    public function testInvalidConstructorModeInvalid()
    {
        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(9, 1);
    }

    public function testFromCspString()
    {
        $csp = ContentSecurityPolicy::fromCspString('default-src https://www.tom.be');
        $this->assertInstanceOf(ContentSecurityPolicy::class, $csp);
    }

    public function testToCspString()
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_VALUE_ONLY);

        $csp->addToDirective('default-src', "'self'");
        $this->assertEquals("default-src 'self';", (string)$csp);

        $csp->addToDirective('default-src', "https://www.tom.be");
        $this->assertEquals("default-src 'self' https://www.tom.be;", (string)$csp);

        $csp->addToDirective('script-src', "'unsafe-inline'");
        $this->assertEquals("default-src 'self' https://www.tom.be; script-src 'unsafe-inline';", (string)$csp);

        $csp->addToDirective('sandbox', null);
        $this->assertEquals("default-src 'self' https://www.tom.be; sandbox; script-src 'unsafe-inline';", (string)$csp);

        $csp->addToDirective('sandbox', 'allow-popups');
        $this->assertEquals("default-src 'self' https://www.tom.be; sandbox allow-popups; script-src 'unsafe-inline';", (string)$csp);

        $csp->addToDirective('report-to', 'my-endpoint');
        $this->assertEquals("default-src 'self' https://www.tom.be; report-to my-endpoint; sandbox allow-popups; script-src 'unsafe-inline';", (string)$csp);
    }

    public function testToCspStringFull()
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_FULL_HEADER);

        $csp->addToDirective('default-src', "'self'");
        $this->assertEquals("Content-Security-Policy: default-src 'self';", (string)$csp);

        $csp->setReportOnly(true);
        $this->assertEquals("Content-Security-Policy-Report-Only: default-src 'self';", (string)$csp);
    }

    public function testNonExistingDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        $this->assertNull($csp->getDirective('default-src'));
    }

    public function testSettersAndGetters(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        $csp->setMode(ContentSecurityPolicy::MODE_LOOSE);
        $this->assertEquals(ContentSecurityPolicy::MODE_LOOSE, $csp->getMode());
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_VALUE_ONLY);
        $this->assertEquals(ContentSecurityPolicy::OUTPUT_VALUE_ONLY, $csp->getOutputMode());
    }

    public function testBaseUriDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        foreach (["'self'", "'unsafe-eval'", "'nonce-ThisIsANonce123=='", 'http:', 'https://www.tom.be'] as $item) {
            $csp->addToDirective('base-uri', $item);
            $this->assertArrayHasKey($item, $csp->getDirective('base-uri'));
        }
    }

    public function testChildSrcDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        foreach (["'self'", "'unsafe-eval'", "'nonce-ThisIsANonce123=='", 'http:', 'https://www.tom.be'] as $item) {
            $csp->addToDirective('child-src', $item);
            $this->assertArrayHasKey($item, $csp->getDirective('child-src'));
        }
    }

    public function testFormActionDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        foreach (["'self'", "'unsafe-eval'", "'nonce-ThisIsANonce123=='", 'http:', 'https://www.tom.be'] as $item) {
            $csp->addToDirective('form-action', $item);
            $this->assertArrayHasKey($item, $csp->getDirective('form-action'));
        }
    }

    public function testFrameAncestorsDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT);
        foreach (["'self'", 'http:', 'https://www.tom.be'] as $item) {
            $csp->addToDirective('frame-ancestors', $item);
            $this->assertArrayHasKey($item, $csp->getDirective('frame-ancestors'));
        }
    }
}