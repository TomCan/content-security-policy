<?php


namespace TomCan\Csp;


use TomCan\Csp\Exception\CspInvalidDirectiveException;
use TomCan\Csp\Exception\CspInvalidSourceListItemException;

class CspParser
{

    const MODE_STRICT = 0;
    const MODE_LOOSE = 1;

    private int $mode;
    private int $level;

    public function __construct(int $mode = self::MODE_STRICT, int $level = 3)
    {
        $this->mode = $mode;
        $this->level = $level;
    }

    public function parse($cspString): array
    {
        // Trim any leading or trailing spaces
        $cspString = trim($cspString);

        // initialize array
        $values = [];

        // check to see if full header, or header value only
        if (preg_match('/^content-security-policy(-report-only)?\s*:(.*)/i', $cspString, $matches)) {
            // check if report-only
            if ($matches[1]) {
                $values['report']['report-only'] = true;
            }
            // full header, only keep second part
            $cspString = trim($matches[2]);
        }

        // split on ;
        $items = explode(';', $cspString);
        foreach ($items as $item) {
            // split on space
            $parts = explode(" ", trim($item));
            // first part contains the directive
            $directive = strtolower(array_shift($parts));
            $predefined = [];
            switch ($directive) {
                case 'script-src':
                    $predefined[] = "unsafe-eval";
                // no break
                case 'style-src':
                    $predefined[] = "unsafe-inline";
                // no break;
                case 'default-src':
                case 'img-src':
                case 'font-src':
                case 'connect-src':
                case 'media-src':
                case 'object-src':
                case 'frame-src':
                    $predefined[] = "none";
                    $predefined[] = "self";
                    break;
                case 'report-uri':
                case 'report-to':
                    break;
                case '':
                    // empty part, skip
                    break;
                default:
                    // we don't know this directive, throw exception
                    if ($this->mode == self::MODE_STRICT) {
                        throw new CspInvalidDirectiveException('Unknown directive "' . $directive . "'");
                    }
            }

            // add values
            $predefined_pattern_general = '/^\'.*\'$/';
            $predefined_pattern = '/^\'' . implode('|',$predefined) . '\'$/i';
            foreach ($parts as $part) {
                // predefined value
                if (preg_match($predefined_pattern, $part)) {
                    $values[$directive][$part] = $part;
                } else {
                    if (preg_match($predefined_pattern_general, $part)) {
                        // invalid pre-defined value for this directive
                        if ($this->mode == self::MODE_STRICT) {
                            throw new CspInvalidSourceListItemException('Invalid source-list item ' . $part . ' for directive ' . $directive);
                        }
                    } else {
                        // regular value
                        $values[$directive][$part] = $part;
                    }
                }
            }

        }

        return $values;
    }
}