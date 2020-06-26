<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use TomCan\Csp\ContentSecurityPolicy;

class CspTest extends TestCase
{

    public function testConstructor()
    {
        foreach ([ContentSecurityPolicy::MODE_STRICT, ContentSecurityPolicy::MODE_LOOSE] as $mode) {
            foreach ([ContentSecurityPolicy::LEVEL_1, ContentSecurityPolicy::LEVEL_2, ContentSecurityPolicy::LEVEL_3] as $level) {
                $csp = new ContentSecurityPolicy($mode, $level);
                $this->assertEquals($mode, $csp->getMode());
                $this->assertEquals($level, $csp->getLevel());
            }
        }
    }

    public function testInvalidConstructorLevelLow()
    {
        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 0);
    }

    public function testInvalidConstructorLevelHigh()
    {
        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 4);
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
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 3);
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_VALUE_ONLY);

        $csp->addToDirective('default-src', "'self'");
        $this->assertEquals("default-src 'self';", (string)$csp);

        $csp->addToDirective('default-src', "https://www.tom.be");
        $this->assertEquals("default-src 'self' https://www.tom.be;", (string)$csp);

        $csp->addToDirective('script-src', "'unsafe-inline'");
        $this->assertEquals("default-src 'self' https://www.tom.be; script-src 'unsafe-inline';", (string)$csp);

        $csp->addToDirective('sandbox', null);
        $this->assertEquals("default-src 'self' https://www.tom.be; script-src 'unsafe-inline'; sandbox;", (string)$csp);

        $csp->addToDirective('sandbox', 'allow-popups');
        $this->assertEquals("default-src 'self' https://www.tom.be; script-src 'unsafe-inline'; sandbox allow-popups;", (string)$csp);

        $csp->addToDirective('report-to', 'my-endpoint');
        $this->assertEquals("default-src 'self' https://www.tom.be; script-src 'unsafe-inline'; report-to my-endpoint; sandbox allow-popups;", (string)$csp);
    }

    public function testToCspStringFull()
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 3);
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_FULL_HEADER);

        $csp->addToDirective('default-src', "'self'");
        $this->assertEquals("Content-Security-Policy: default-src 'self';", (string)$csp);

        $csp->setReportOnly(true);
        $this->assertEquals("Content-Security-Policy-Report-Only: default-src 'self';", (string)$csp);
    }

    public function testNonExistingDirective(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 3);
        $this->assertNull($csp->getDirective('default-src'));
    }

    public function testSettersAndGetters(): void
    {
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 3);
        $csp->setLevel(1);
        $this->assertEquals(1, $csp->getLevel());
        $csp->setMode(ContentSecurityPolicy::MODE_LOOSE);
        $this->assertEquals(ContentSecurityPolicy::MODE_LOOSE, $csp->getMode());
        $csp->setOutputMode(ContentSecurityPolicy::OUTPUT_VALUE_ONLY);
        $this->assertEquals(ContentSecurityPolicy::OUTPUT_VALUE_ONLY, $csp->getOutputMode());
    }
}