<?php


namespace TomCan\Csp;


use TomCan\Csp\Exception\CspInvalidDirectiveException;
use TomCan\Csp\Exception\CspInvalidSourceListItemException;

class CspParser
{

    // specs define base64-value as 1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )
    // basic matching, need at least 1 character, ending in 0, 1 or 2 =
    const BASE64_PATTERN = '[A-Za-z0-9+\/]+={0,2}';

    private int $mode;
    private int $level;

    public function __construct(int $mode = ContentSecurityPolicy::MODE_STRICT, int $level = 3)
    {
        $this->mode = $mode;
        $this->level = $level;
    }

    public function parse($cspString): ContentSecurityPolicy
    {
        // Trim any leading or trailing spaces
        $cspString = trim($cspString);

        // initialize array
        $csp = new ContentSecurityPolicy($this->mode, $this->level);

        // check to see if full header, or header value only
        if (preg_match('/^content-security-policy(-report-only)?\s*:(.*)/i', $cspString, $matches)) {
            // check if report-only
            if ($matches[1]) {
                $csp->setReportOnly(true);
            }
            // full header, only keep second part
            $cspString = trim($matches[2]);
        }

        // split on ;
        $items = explode(';', $cspString);
        foreach ($items as $item) {
            // split on space
            $parts = explode(" ", trim($item));

            $directive = strtolower(array_shift($parts));
            // sandbox can have empty value
            if (count($parts) == 0 && $directive == ContentSecurityPolicy::DIRECTIVE_SANDBOX) {
                $csp->addToDirective($directive, null);
            } else {
                foreach ($parts as $part) {
                    $csp->addToDirective($directive, $part);
                }
            }
        }

        return $csp;
    }
}