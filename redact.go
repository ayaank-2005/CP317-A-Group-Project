package redact

import "regexp"

// the 'Result' contains the values saved with each report submission.
type Result struct {
	Content string
	Count   int
}

type rule struct {
	pattern *regexp.Regexp
	label   string
}

// For the name rule, only the captured name is replaced.
// For the other rules, the entire match is replaced.
var rules = []rule{
	{
		pattern: regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
		label:   "[EMAIL]",
	},
	{
		pattern: regexp.MustCompile(`(?i)(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)|\b[2-9][0-9]{2})[ .-]?[2-9][0-9]{2}[ .-]?[0-9]{4}\b(?:[ \t]*(?:ext\.?|x)[ \t]*[0-9]+)?`),
		label:   "[PHONE]",
	},
	{
		pattern: regexp.MustCompile(`\b[0-9](?:[ -]?[0-9]){12,15}\b`),
		label:   "[CARD]",
	},
	{
		pattern: regexp.MustCompile(`\b[0-9]{3}[ -][0-9]{3}[ -][0-9]{3}\b`),
		label:   "[SIN]",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b[0-9]{1,6}[ \t]+(?:[A-Z][A-Z.'’-]*[ \t]+){1,5}(?:street|st|road|rd|avenue|ave|drive|dr|lane|ln|court|ct|boulevard|blvd|crescent|cres)\b(?:[ \t]+(?:north|south|east|west|n|s|e|w)\b)?(?:,?[ \t]+(?:unit|apt\.?|suite)[ \t]+[A-Z0-9-]+)?`),
		label:   "[ADDRESS]",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b[ABCEGHJ-NPRSTVXY][0-9][ABCEGHJ-NPRSTVWXYZ][ -]?[0-9][ABCEGHJ-NPRSTVWXYZ][0-9]\b`),
		label:   "[POSTAL_CODE]",
	},
	{
		pattern: regexp.MustCompile(`(?i:\bmy name is|\bmy name['’]s)[ \t]+(\p{Lu}[\p{L}'’-]*(?:[ \t]+\p{Lu}[\p{L}'’-]*){0,3})`),
		label:   "[NAME]",
	},
}

// Mask replaces recognized personal details and counts each replacement.
func Mask(text string) Result {
	result := Result{Content: text}

	for _, r := range rules {
		matches := r.pattern.FindAllStringSubmatchIndex(result.Content, -1)

		// Working backwards so replacing text does not shift earlier positions.
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			start, end := match[0], match[1]

			if len(match) > 2 {
				start, end = match[2], match[3]
			}

			result.Content = result.Content[:start] + r.label + result.Content[end:]
			result.Count++
		}
	}

	return result
}
