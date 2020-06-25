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

    public function testInvalidConstructor()
    {
        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 0);

        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(ContentSecurityPolicy::MODE_STRICT, 4);

        $this->expectException(\InvalidArgumentException::class);
        $csp = new ContentSecurityPolicy(2, 1);
    }

    public function testFromCspString()
    {
        $csp = ContentSecurityPolicy::fromCspString('default-src https://www.tom.be');
        $this->assertInstanceOf(ContentSecurityPolicy::class, $csp);
    }

}