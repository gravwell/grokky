//
// Copyright (c) 2016-2017 Konstanin Ivanov <kostyarin.ivanov@gmail.com>.
// All rights reserved. This program is free software. It comes without
// any warranty, to the extent permitted by applicable law. You can
// redistribute it and/or modify it under the terms of the Do What
// The Fuck You Want To Public License, Version 2, as published by
// Sam Hocevar. See LICENSE file for more details or see below.
//

//
//        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//

package grokky

type patternPair struct {
	name    string
	pattern string
}

var basePairs = []patternPair{
	patternPair{"USERNAME", `[a-zA-Z0-9._-]+`},
	patternPair{"USER", `%{USERNAME}`},
	patternPair{"EMAILLOCALPART", `[a-zA-Z][a-zA-Z0-9_.+-=:]+`},
	patternPair{"HOSTNAME", `\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*(\.?|\b)`},
	patternPair{"EMAILADDRESS", `%{EMAILLOCALPART}@%{HOSTNAME}`},
	patternPair{"HTTPDUSER", `%{EMAILADDRESS}|%{USER}`},
	patternPair{"INT", `[+-]?(?:[0-9]+)`},
	patternPair{"BASE10NUM", `[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))`},
	patternPair{"NUMBER", `%{BASE10NUM}`},
	patternPair{"BASE16NUM", `[+-]?(?:0x)?(?:[0-9A-Fa-f]+)`},
	patternPair{"BASE16FLOAT", `\b[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+))\b`},
	//
	patternPair{"POSINT", `\b[1-9][0-9]*\b`},
	patternPair{"NONNEGINT", `\b[0-9]+\b`},
	patternPair{"WORD", `\b\w+\b`},
	patternPair{"NOTSPACE", `\S+`},
	patternPair{"SPACE", `\s*`},
	patternPair{"DATA", `.*?`},
	patternPair{"GREEDYDATA", `.*`},
	patternPair{"QUOTEDSTRING", `("(\\.|[^\\"]+)+")|""|('(\\.|[^\\']+)+')|''|` +
		"(`(\\\\.|[^\\\\`]+)+`)|``"},
	patternPair{"UUID", `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`},
	// Networking
	patternPair{"CISCOMAC", `(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}`},
	patternPair{"WINDOWSMAC", `(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}`},
	patternPair{"COMMONMAC", `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`},
	patternPair{"MAC", `%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}`},
	patternPair{"IPV6", `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`},
	patternPair{"IPV4", `(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))`},
	patternPair{"IP", `%{IPV6}|%{IPV4}`},
	patternPair{"IPORHOST", `%{IP}|%{HOSTNAME}`},
	patternPair{"HOSTPORT", `%{IPORHOST}:%{POSINT}`},

	// paths
	patternPair{"UNIXPATH", `(/([\w_%!$@:.,~-]+|\\.)*)+`},
	patternPair{"TTY", `/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+)`},
	patternPair{"WINPATH", `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`},
	patternPair{"PATH", `%{UNIXPATH}|%{WINPATH}`},
	patternPair{"URIPROTO", `[A-Za-z]+(\+[A-Za-z+]+)?`},
	patternPair{"URIHOST", `%{IPORHOST}(?::%{POSINT:port})?`},
	// uripath comes loosely from RFC1738, but mostly from what Firefox
	// doesn't turn into %XX
	patternPair{"URIPATH", `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+`},
	patternPair{"URIPARAM", `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`},
	patternPair{"URIPATHPARAM", `%{URIPATH}(?:%{URIPARAM})?`},
	patternPair{"URI", `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`},
	// Months: January, Feb, 3, 03, 12, December
	patternPair{"MONTH", `\bJan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?\b`},
	patternPair{"MONTHNUM", `0?[1-9]|1[0-2]`},
	patternPair{"MONTHNUM2", `0[1-9]|1[0-2]`},
	patternPair{"MONTHDAY", `(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]`},
	// Days: Monday, Tue, Thu, etc...
	patternPair{"DAY", `Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?`},
	// Years?
	patternPair{"YEAR", `(?:\d\d){1,2}`},
	patternPair{"HOUR", `2[0123]|[01]?[0-9]`},
	patternPair{"MINUTE", `[0-5][0-9]`},
	// '60' is a leap second in most time standards and thus is valid.
	patternPair{"SECOND", `(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?`},
	patternPair{"TIME", `%{HOUR}:%{MINUTE}:%{SECOND}`},
	// datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)
	patternPair{"DATE_US", `%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}`},
	patternPair{"DATE_EU", `%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}`},
	// I really don't know how it's called
	patternPair{"DATE_X", `%{YEAR}/%{MONTHNUM2}/%{MONTHDAY}`},
	patternPair{"ISO8601_TIMEZONE", `Z|[+-]%{HOUR}(?::?%{MINUTE})`},
	patternPair{"ISO8601_SECOND", `%{SECOND}|60`},
	patternPair{"TIMESTAMP_ISO8601", `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`},
	patternPair{"DATE", `%{DATE_US}|%{DATE_EU}|%{DATE_X}`},
	patternPair{"DATESTAMP", `%{DATE}[- ]%{TIME}`},
	patternPair{"TZ", `[A-Z]{3}`},
	patternPair{"NUMTZ", `[+-]\d{4}`},
	patternPair{"DATESTAMP_RFC822", `%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}`},
	patternPair{"DATESTAMP_RFC2822", `%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}`},
	patternPair{"DATESTAMP_OTHER", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}`},
	patternPair{"DATESTAMP_EVENTLOG", `%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}`},
	patternPair{"HTTPDERROR_DATE", `%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}`},
	// golang time patterns
	patternPair{"ANSIC", `%{DAY} %{MONTH} [_123]\d %{TIME} %{YEAR}"`},
	patternPair{"UNIXDATE", `%{DAY} %{MONTH} [_123]\d %{TIME} %{TZ} %{YEAR}`},
	patternPair{"RUBYDATE", `%{DAY} %{MONTH} [0-3]\d %{TIME} %{NUMTZ} %{YEAR}`},
	patternPair{"RFC822Z", `[0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`},
	patternPair{"RFC850", `%{DAY}, [0-3]\d-%{MONTH}-%{YEAR} %{TIME} %{TZ}`},
	patternPair{"RFC1123", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{TZ}`},
	patternPair{"RFC1123Z", `%{DAY}, [0-3]\d %{MONTH} %{YEAR} %{TIME} %{NUMTZ}`},
	patternPair{"RFC3339", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}%{ISO8601_TIMEZONE}`},
	patternPair{"RFC3339NANO", `%{YEAR}-[01]\d-[0-3]\dT%{TIME}\.\d{9}%{ISO8601_TIMEZONE}`},
	patternPair{"KITCHEN", `\d{1,2}:\d{2}(AM|PM|am|pm)`},
	// Syslog Dates: Month Day HH:MM:SS
	patternPair{"SYSLOGTIMESTAMP", `%{MONTH} +%{MONTHDAY} %{TIME}`},
	patternPair{"PROG", `[\x21-\x5a\x5c\x5e-\x7e]+`},
	patternPair{"SYSLOGPROG", `%{PROG:program}(?:\[%{POSINT:pid}\])?`},
	patternPair{"SYSLOGHOST", `%{IPORHOST}`},
	patternPair{"SYSLOGFACILITY", `<%{NONNEGINT:facility}.%{NONNEGINT:priority}>`},
	patternPair{"HTTPDATE", `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`},
	// Shortcuts
	patternPair{"QS", `%{QUOTEDSTRING}`},
	// Log Levels
	patternPair{"LOGLEVEL", `[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?`},
	// Log formats
	patternPair{"SYSLOGBASE", `%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`},
	patternPair{"COMMONAPACHELOG", `%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`},
	patternPair{"COMBINEDAPACHELOG", `%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}`},
	patternPair{"HTTPD20_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}`},
	patternPair{"HTTPD24_ERRORLOG", `\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}:tid %{NUMBER:tid}\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}`},
	patternPair{"HTTPD_ERRORLOG", `%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}`},

	//
}
